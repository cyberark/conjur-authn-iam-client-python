#!/usr/bin/env groovy

pipeline {
//   agent { label 'executor-v2' }
  agent any
  options {
    ansiColor('xterm')
    timestamps()
    buildDiscarder(logRotator(daysToKeepStr: '30'))
  }

//   triggers {
//     cron(getDailyCronString())
//   }

  stages {
    stage('Test workflow') {
      steps {
        sh './test.sh'
      }
    }
  }

  post {
    always {
      script {
        cleanupAndNotify(currentBuild.currentResult)
      }
    }
  }
}
