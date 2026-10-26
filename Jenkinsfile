pipeline {
    agent any

    options {
        timeout(time: 10, unit: 'MINUTES')
    }

    stages {
        stage('Test') {
            steps {
                sh 'go version'
                sh 'go test -v ./...'
            }
        }
    }
}
