pipeline {
    agent any

    parameters {
        booleanParam(name: 'REQUIRE_NATIVE_RVV', defaultValue: false,
                     description: 'Require AVX-512 generated-code tests; missing hardware is a failure')
    }

    triggers {
        githubPush()
    }
    stages {
        stage('RVV runner checks') {
            steps {
                sh 'PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p "test_benchmark_checker.py" -v'
                sh 'PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p "test_rvv_*.py" -v'
            }
        }
        stage('Build') {
            steps {
                echo 'Build the project'
                sh 'git submodule update --init --recursive'
                sh 'chmod +x ./scripts/build.sh'
                sh './scripts/build.sh 20'
            }
        }

        stage('Focused C++ regressions') {
            steps {
                script {
                    def required = params.REQUIRE_NATIVE_RVV ? 'ON' : 'OFF'
                    sh "cmake -S . -B build-llvm-20 -DBUILD_TESTING=ON -DRVDBT_NATIVE_REQUIRED=${required}"
                }
                sh 'cmake --build build-llvm-20 --target regression-focused --parallel 4'
                sh 'ctest --test-dir build-llvm-20 -L focused --output-on-failure --no-tests=error'
            }
        }

        stage('Test') {
            steps {
                echo 'Run tests'
                sh 'chmod +x ./scripts/test.sh'
                sh './scripts/test.sh 20'
            }
        }

        stage('Benchmark') {
            steps {
                echo 'Run benchmarks'
                sh 'chmod +x ./scripts/benchmark.sh'
                sh './scripts/benchmark.sh 20'
            }
        }
    }
    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed. Check logs for details.'
        }
    }
}
