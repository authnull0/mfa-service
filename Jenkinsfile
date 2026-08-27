pipeline {
    agent any

    environment {
        GITHUB_REPO = 'https://github.com/authnull0/mfa-service.git'
        GITHUB_BRANCH = 'onprem'
        PUBLIC_TAG  = '1.0.0-onprem'
        DOCKER_REGISTRY_PUBLIC= 'docker-repo-public-v2.authnull.com'
        DOCKER_PUBLIC_CREDENTIALS = credentials('docker-repo-public-v2')
        DOCKER_IMAGE_PUBLIC = "docker-repo-public-v2.authnull.com/mfa-service:${PUBLIC_TAG}"
//        AZURE_CLIENT_ID = credentials('clientid')  
//        AZURE_CLIENT_SECRET = credentials('secretid') 
//        AZURE_TENANT_ID = credentials('tenantid')
//        AZURE_SUBSCRIPTION_ID = credentials('subscriptionId')
//        AKS_CLUSTER = 'authnull-v2'
//        RESOURCE_GROUP = 'azure-k8s'
//        K8S_NAMESPACE = 'authnull-dev'
        GITHUB_TOKEN = credentials('ram-Github-credentials')

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
                // Build Stage

        stage('Build Public Image') {
            steps {
                sh """
                    echo "Building PUBLIC image: ${DOCKER_IMAGE_PUBLIC}"
                    docker build -t ${DOCKER_IMAGE_PUBLIC} .
                """
            }
        }

        // Push Stage

        stage('Push Public Image') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-repo-public-v2', usernameVariable: 'USR', passwordVariable: 'PASS')]) {
                    sh """
                        echo "Logging in to PUBLIC registry"
                        echo "\$PASS" | docker login ${DOCKER_REGISTRY_PUBLIC} -u "\$USR" --password-stdin

                        docker push ${DOCKER_IMAGE_PUBLIC}
                        docker logout ${DOCKER_REGISTRY_PUBLIC}
                    """
                }
            }
        }

        // Cleanup Stage

        stage('Cleanup Images') {
            steps {
                sh """
                    docker rmi ${DOCKER_IMAGE_PUBLIC} || true
                """
            }
        }
    }
}
