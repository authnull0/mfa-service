pipeline {
    agent any

    environment {
        GITHUB_REPO = 'https://github.com/authnull0/mfa-service.git'
        GITHUB_BRANCH = 'production-az'
        DOCKER_REGISTRY = 'docker-repo.authnull.com'
        DOCKER_REGISTRY_CREDENTIALS = credentials('authnull-repo')
        DOCKER_IMAGE = 'docker-repo.authnull.com/mfa-service:production'
        AZURE_CLIENT_ID = credentials('clientid')  
        AZURE_CLIENT_SECRET = credentials('secretid') 
        AZURE_TENANT_ID = credentials('tenantid')
        AZURE_SUBSCRIPTION_ID = credentials('subscriptionId')
        AKS_CLUSTER = 'authnull-v2'
        RESOURCE_GROUP = 'azure-k8s'
        K8S_NAMESPACE = 'authnull-dev'
        GITHUB_TOKEN = credentials('my-test-token')

    }

    triggers {
        githubPush()
    }
    options {
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '10', daysToKeepStr: '', numToKeepStr: '10')
    }
    stages {
        stage('Checkout') {
            steps {
                 checkout scm
            }
        }
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t ${DOCKER_IMAGE} .'
            }
        }
        stage('Login to Docker Artifactory') {
            steps {
                sh 'echo ${DOCKER_REGISTRY_CREDENTIALS_PSW} | docker login ${DOCKER_REGISTRY} -u ${DOCKER_REGISTRY_CREDENTIALS_USR} --password-stdin'
            }
        }
        stage('Push Docker Image') {
            steps {
                sh 'docker push ${DOCKER_IMAGE}'
            }
        }
        stage('Logout from Docker Artifactory') {
            steps {
                sh 'docker logout ${DOCKER_REGISTRY}'
            }
        }
        stage('Remove Docker Image') {
            steps {
                sh 'docker rmi ${DOCKER_IMAGE}'
            }
        }
    }       
}     
