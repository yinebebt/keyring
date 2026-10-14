pipeline {
    agent any

    stages {
        stage('Test') {
            steps {
                sh 'go version'
                sh 'go test ./...'
            }
        }
    }
}
