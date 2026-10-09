pipeline {
    agent any

    triggers {
        githubPush()
    }
    stages {
        stage('RVV runner checks') {
            steps {
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
