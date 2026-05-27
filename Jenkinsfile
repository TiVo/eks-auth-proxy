@Library('tivoPipeline') _

emailBreaks('inception-scrum@tivo.com') {
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
