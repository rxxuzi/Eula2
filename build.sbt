ThisBuild / version := "0.2.0"

ThisBuild / scalaVersion := "2.13.13"

lazy val root = (project in file("."))
  .settings(
    name := "Eula2"
  )

// https://mvnrepository.com/artifact/org.lz4/lz4-java
libraryDependencies += "org.lz4" % "lz4-java" % "1.8.0"

