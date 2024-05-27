# Async cluster sharding DTLS Server

## Usage

### Local cluster sharding

1. Start seed node

    ```shell
    mvn exec:java -Dexec.mainClass="io.kaxis.Application" -Dexec.args="4684"
    mvn exec:java -Dexec.mainClass="io.kaxis.Application" -Dexec.args="4685"
    ```

    there two seed node `must` to be start first.

    ```text
    cluster {
      # This can also be defined as Java system properties when starting the JVM using the following syntax:
      #
      # -Dpekko.cluster.seed-nodes.0=pekko://kaxis@seed1:2552
      # -Dpekko.cluster.seed-nodes.1=pekko://kaxis@seed2:2552
      #
      seed-nodes = [
        "pekko://kaxis@127.0.0.1:4684",
        "pekko://kaxis@127.0.0.1:4685"]
      seed-nodes = ${?SEED_NODES}
      roles = ["seed", "sharding"]
      roles = ${?ROLES}
      sharding.role = "sharding"
      sharding.role = ${?SHARDING_ROLE}
      min-nr-of-members = 2
    ```

2. Join worker node.

    ```shell
    mvn exec:java -Dexec.mainClass="io.kaxis.Application" -Dexec.args="4687"
    mvn exec:java -Dexec.mainClass="io.kaxis.Application" -Dexec.args="4688"
    mvn exec:java -Dexec.mainClass="io.kaxis.Application" -Dexec.args="4689"
    ```

### Kubernetes cluster sharding

  [statefulSet.yaml](kubernetes/statefulSet.yaml)

## Scala version high performance with ZIO

  Have a glance at my [async-sharding-dtls](https://github.com/barudisshu/async-sharding-dtls) repo. A more Functional,
  Type Level program you need to know.
