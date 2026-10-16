	// Family-A oracle: load profiled stable-load (PC,value) pairs and enable substitution.
	if (const char *slf = getenv("DBT_STABLE_LOAD_FILE")) {
		FILE *f = fopen(slf, "r");
		if (f) {
			unsigned pc, val; int n = 0;
			while (fscanf(f, "%x,%x\n", &pc, &val) == 2) { dbt::add_stable_load(pc, val); n++; }
			fclose(f);
			dbt::config::subst_stable_loads = (n > 0);
			fprintf(stderr, "STABLE_LOADS_LOADED=%d\n", n);
		}
	}
	// C2 ceiling oracle correction: load profiled (jalr_pc,target) pairs and skip Create_gbrind
	// entirely for those sites -- see config::subst_stable_jalr's comment.
	if (const char *sjf = getenv("DBT_STABLE_JALR_FILE")) {
		FILE *f = fopen(sjf, "r");
		if (f) {
			unsigned pc, tgt; int n = 0;
			while (fscanf(f, "%x,%x\n", &pc, &tgt) == 2) { dbt::add_stable_jalr_target(pc, tgt); n++; }
			fclose(f);
			dbt::config::subst_stable_jalr = (n > 0);
			fprintf(stderr, "STABLE_JALR_LOADED=%d\n", n);
		}
	}
