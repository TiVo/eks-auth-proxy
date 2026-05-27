@Library('tivoPipeline') _

emailBreaks {
    node('docker') {
        stage('Code Checkout') {
            checkout scm
        }
        stage('Build info') {
            sh './gradlew build'
        }
        stage('Build Docker Image') {
            buildDocker 'eks-auth-proxy', 'Dockerfile'
        }
    }
}
