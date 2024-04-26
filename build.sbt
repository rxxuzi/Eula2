ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.13"

lazy val root = (project in file("."))
  .settings(
    name := "Eula2"
  )

// https://mvnrepository.com/artifact/org.lz4/lz4-java
libraryDependencies += "org.lz4" % "lz4-java" % "1.8.0"

