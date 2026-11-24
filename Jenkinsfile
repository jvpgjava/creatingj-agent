pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 20, unit: 'MINUTES')
    }

    environment {
        CARGO_TERM_COLOR = 'never'
        RUST_BACKTRACE = '1'
    }

    stages {
        stage('Toolchain') {
            steps {
                sh 'rustc --version && cargo --version && rustfmt --version && cargo clippy --version'
            }
        }

        stage('Format Check') {
            steps {
                sh 'cargo fmt --all -- --check'
            }
        }

        stage('Clippy') {
            steps {
                sh 'cargo clippy --workspace --all-targets -- -D warnings'
            }
        }

        stage('Test Workspace') {
            steps {
                sh 'cargo test --workspace --locked'
            }
        }

        stage('Build Release Binaries') {
            steps {
                sh 'cargo build --release --locked --bin creatingj --bin creatingj-runner'
                sh './target/release/creatingj --version && ./target/release/creatingj-runner --version'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'target/release/creatingj,target/release/creatingj-runner', allowEmptyArchive: true
        }
    }
}
