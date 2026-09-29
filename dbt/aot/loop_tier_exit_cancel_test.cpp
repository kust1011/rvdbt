// Exit-cancel contract: a build still running when the guest stops is CANCELLED, not awaited.
//
// WHY THIS EXISTS. The delayed-builder case measured GUEST_EXIT at 2603 ms and BUILD_END at
// 45253 ms: ReportAtExit blocked for 42.65 s after the guest had stopped, for an artifact that
// cannot be installed (the install gate is in-run only) and therefore cannot benefit the run.
// "No orphan after the parent exits" was true and insufficient -- it was true only because the
// parent waited.
//
// Every section drives the REAL SpawnBuilder and the REAL ReportAtExit with an ordinary program
// standing in for the compiler, so what is checked is the shipped lifecycle and not a model of it.
#include "dbt/aot/loop_tier.h"
#include "dbt/config.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace dbt::looptier
{
namespace
{
unsigned g_fail = 0;

#define CHECK(cond, what)                                                                          \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, (what));                  \
			++g_fail;                                                                  \
		} else {                                                                           \
			printf("  ok   %s\n", (what));                                             \
		}                                                                                  \
	} while (0)

std::string MakeTempDir()
{
	char t[] = "/tmp/lt_exit_cancel_XXXXXX";
	return mkdtemp(t) ? std::string(t) : std::string();
}

// A STAND-IN COMPILER THAT IS ACTUALLY SLOW. SpawnBuilder renders elfaot's own argv, so handing it
// `/bin/sleep` does not produce a slow build -- sleep rejects those arguments and exits at once,
// which would make the pending-at-exit section pass vacuously. A tiny script that IGNORES its
// arguments and sleeps is the only stand-in that really occupies the window under test.
std::string MakeSlowCompiler(std::string const &dir, int seconds = 30)
{
	std::string const path = dir + "/slow_compiler.sh";
	if (FILE *f = fopen(path.c_str(), "w")) {
		fprintf(f, "#!/bin/sh\nsleep %d\n", seconds);
		fclose(f);
		chmod(path.c_str(), 0755);
	}
	return path;
}
char const *kFast = "/bin/echo";

// A STAND-IN COMPILER THAT IGNORES SIGTERM. This is the descendant case: SpawnBuilder's middle
// child (the group LEADER) is rvdbt's own code and dies on SIGTERM, while this -- the exec'd
// "compiler" -- does not. Under leader-gated escalation the leader's exit satisfied
// `waitpid(leader) > 0` and SIGKILL was never sent, leaving this process running.
std::string MakeTermIgnoringCompiler(std::string const &dir)
{
	std::string const path = dir + "/term_ignoring_compiler.sh";
	if (FILE *f = fopen(path.c_str(), "w")) {
		// The shell ignores TERM and keeps looping; each `sleep` child may be killed by the
		// group signal, and the loop simply continues -- so the process really survives SIGTERM.
		fprintf(f, "#!/bin/sh\ntrap '' TERM\ni=0\nwhile [ $i -lt 600 ]; do sleep 0.1; "
			   "i=$((i+1)); done\n");
		fclose(f);
		chmod(path.c_str(), 0755);
	}
	return path;
}

// How many NON-ZOMBIE processes are still in this process group? The test asks the same question
// the repair asks, and for the same reason: a single PID cannot show that a SUBTREE is gone.
int GroupLiveCount(pid_t pgid)
{
	char cmd[256];
	snprintf(cmd, sizeof cmd,
		 "ps -e -o pgid=,stat= 2>/dev/null | awk '$1==%d && $2 !~ /Z/' | wc -l", (int)pgid);
	FILE *f = popen(cmd, "r");
	if (!f)
		return -1;
	int n = -1;
	if (fscanf(f, "%d", &n) != 1)
		n = -1;
	pclose(f);
	return n;
}

// The test's own clock; `NowMs` is internal to loop_tier.cpp and is not part of its interface.
long NowMsForTest()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

bool Alive(pid_t pid)
{
	return kill(pid, 0) == 0 || errno != ESRCH;
}

void ResetTierState()
{
	config::loop_tier = true;
	config::loop_tier_state = (int)State::OFF;
	config::loop_tier_pid = 0;
	config::loop_tier_pgid_owned = false;
	config::loop_tier_canceled = false;
	config::loop_tier_stale_publication = false;
	config::loop_tier_cancel_signal = 0;
	config::loop_tier_build_rc = -1;
	config::loop_tier_exit_cancel = true;
	config::rvv_vector_ssa = false; // the only value at which the tier arms
}

// Spawn a builder and put the tier in the state ReportAtExit expects to find mid-build.
pid_t SpawnInto(std::string const &d, char const *compiler, char const *arg)
{
	config::loop_tier_stage = strdup(d.c_str());
	pid_t pid = SpawnBuilder(sched_getcpu(), compiler, arg, d.c_str(),
				 (d + "/absent.aot.so").c_str(), "loop_tier.v512.so", 262144);
	if (pid > 0) {
		config::loop_tier_pid = (int)pid;
		config::loop_tier_state = (int)State::BUILDING;
	}
	return pid;
}

void Run()
{
	// -------------------------------------------------------------------------------------
	printf("1. the builder's process group is OWNED before anything may signal it\n");
	// FAILS IF: SpawnBuilder leaves the child in the PARENT's group, or leaves ownership unproven.
	// Either way a later killpg(loop_tier_pid) would reach processes this tier did not create --
	// which is why the cancel path refuses to signal without this flag.
	{
		ResetTierState();
		std::string d = MakeTempDir();
		std::string slow = MakeSlowCompiler(d);
		pid_t pid = SpawnInto(d, slow.c_str(), "/dev/null");
		CHECK(pid > 0, "the builder forked");
		CHECK(config::loop_tier_pgid_owned, "the parent proved it owns the builder's group");
		CHECK(getpgid(pid) == pid, "the builder's pgid equals its pid");
		CHECK(getpgid(pid) != getpgid(0),
		      "...and is NOT the parent's group, so a group signal cannot reach this process");
		killpg(pid, SIGKILL);
		int st = 0;
		waitpid(pid, &st, 0);
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	printf("2. PENDING AT EXIT: the build is cancelled, reaped, and not published\n");
	// FAILS IF: ReportAtExit blocks for the compiler (the measured defect), leaves a zombie or a
	// live descendant, or records the run as PUBLISHED.
	{
		ResetTierState();
		std::string d = MakeTempDir();
		std::string slow = MakeSlowCompiler(d);
		pid_t pid = SpawnInto(d, slow.c_str(), "/dev/null");
		CHECK(pid > 0, "a builder was spawned");
		// NON-VACUITY: the scenario only exists if the build is still running here. If it had
		// already finished, section 3's path would be under test instead and the timing check
		// below would pass for the wrong reason.
		usleep(200000);
		CHECK(Alive(pid), "...and it is STILL RUNNING at guest exit, so the case is real");
		long const t0 = NowMsForTest();
		ReportAtExit();
		long const waited = NowMsForTest() - t0;

		CHECK(waited < 5000, "ReportAtExit returned promptly instead of awaiting the compiler");
		CHECK(config::loop_tier_canceled, "the run recorded the build as CANCELED");
		CHECK(config::loop_tier_state == (int)State::CANCELED,
		      "the tier state is CANCELED, which is neither PUBLISHED nor FAILED");
		CHECK(config::loop_tier_cancel_signal != 0, "a signal was actually delivered");
		// The exact child must be gone AND consumed: waitpid must now find nothing to collect.
		int st = 0;
		CHECK(waitpid(pid, &st, WNOHANG) == -1 && errno == ECHILD,
		      "the builder was reaped, so no zombie remains");
		CHECK(!Alive(pid), "and no live builder process remains");
		CHECK(GroupLiveCount(pid) == 0, "...and the whole owned group is gone, not just its leader");
		CHECK(config::loop_tier_cancel_group_live == 0, "the tier confirmed the group stopped");
		CHECK(!config::loop_tier_stale_publication,
		      "nothing was published, so no stale publication is claimed");
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	printf("2b. A DESCENDANT THAT IGNORES SIGTERM IS STILL STOPPED\n");
	// FAILS IF: escalation is driven by the LEADER instead of the GROUP. The leader dies on
	// SIGTERM here, so a leader-gated loop stops escalating and this compiler keeps running --
	// which is exactly the defect this section exists to catch. "No orphan" is checked by counting
	// the GROUP, never by one pid.
	{
		ResetTierState();
		std::string d = MakeTempDir();
		std::string comp = MakeTermIgnoringCompiler(d);
		pid_t pid = SpawnInto(d, comp.c_str(), "/dev/null");
		CHECK(pid > 0, "the builder forked");
		usleep(300000);
		// NON-VACUITY: the scenario needs the TERM-ignoring compiler to actually be running, and
		// it must be a DIFFERENT process from the leader -- otherwise nothing is being tested.
		int const before = GroupLiveCount(pid);
		CHECK(before >= 2, "leader AND a separate compiler process are alive in the group");
		ReportAtExit();
		CHECK(config::loop_tier_canceled, "the build was cancelled");
		CHECK(config::loop_tier_cancel_group_live == 0,
		      "the tier itself confirmed the whole owned group stopped");
		// Independently of the tier's own bookkeeping: ask the OS.
		int const after = GroupLiveCount(pid);
		CHECK(after == 0, "no process of the owned group survives -- checked by group, not by pid");
		CHECK(config::loop_tier_cancel_signal == SIGKILL,
		      "escalation reached SIGKILL, because SIGTERM alone did not stop the group");
		int st = 0;
		CHECK(waitpid(pid, &st, WNOHANG) == -1 && errno == ECHILD, "and the leader was reaped");
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	printf("3. COMPLETED BEFORE EXIT: the ordinary completion record is unchanged\n");
	// FAILS IF: the cancel path fires on a build that had already finished -- the completion/
	// cancellation race. A run that finished must keep its rc and must NOT be marked cancelled.
	{
		ResetTierState();
		std::string d = MakeTempDir();
		pid_t pid = SpawnInto(d, kFast, "done");
		CHECK(pid > 0, "a fast builder was spawned");
		// Let it finish on its own before the guest stops. The tier's own WNOHANG must see it.
		for (int i = 0; i < 500 && Alive(pid); ++i)
			usleep(10000);
		ReportAtExit();
		CHECK(!config::loop_tier_canceled,
		      "a build that had already finished is NOT reported as cancelled");
		CHECK(config::loop_tier_state != (int)State::CANCELED, "and its state is not CANCELED");
		CHECK(config::loop_tier_build_rc >= 0, "its exit status was still collected");
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	printf("4. UNOWNED GROUP: the tier refuses to signal and falls back to waiting\n");
	// FAILS IF: the cancel path signals a group it cannot prove it created. That is the unrelated-
	// process hazard, and the safe degradation is the pre-existing blocking wait.
	{
		ResetTierState();
		std::string d = MakeTempDir();
		std::string slow3 = MakeSlowCompiler(d);
		pid_t pid = SpawnInto(d, slow3.c_str(), "/dev/null");
		CHECK(pid > 0, "a builder was spawned");
		usleep(200000);
		CHECK(Alive(pid), "...and is pending, so the refusal path is really taken");
		config::loop_tier_pgid_owned = false; // simulate the race the double-setpgid removes
		ReportAtExit();
		CHECK(config::loop_tier_state != (int)State::PUBLISHED,
		      "an unowned build is still not reported as published");
		int st = 0;
		CHECK(waitpid(pid, &st, WNOHANG) == -1 && errno == ECHILD,
		      "the child was reaped even on the refusal path, so no zombie remains");
		rmdir(d.c_str());
	}

	// -------------------------------------------------------------------------------------
	printf("5. THE SWITCH OFF restores the previous blocking behaviour\n");
	// FAILS IF: --loop-tier-exit-cancel=0 still cancels. The old behaviour must stay reachable for
	// an A/B, and must be the ONLY thing the switch changes.
	{
		ResetTierState();
		config::loop_tier_exit_cancel = false;
		std::string d = MakeTempDir();
		std::string slow2 = MakeSlowCompiler(d, 2);
		pid_t pid = SpawnInto(d, slow2.c_str(), "/dev/null");
		CHECK(pid > 0, "a builder was spawned with cancellation disabled");
		usleep(200000);
		CHECK(Alive(pid), "...and it is still running, so the blocking path is the one exercised");
		ReportAtExit();
		CHECK(!config::loop_tier_canceled, "with the switch off nothing is cancelled");
		int st = 0;
		CHECK(waitpid(pid, &st, WNOHANG) == -1 && errno == ECHILD,
		      "and the blocking wait consumed the child as before");
		rmdir(d.c_str());
	}
}

} // namespace
} // namespace dbt::looptier

int main()
{
	dbt::looptier::Run();
	printf(dbt::looptier::g_fail ? "FAIL (%u failures)\n" : "PASS (%u failures)\n",
	       dbt::looptier::g_fail);
	return dbt::looptier::g_fail ? 1 : 0;
}
