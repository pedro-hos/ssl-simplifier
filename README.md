**Be aware that this project is in Test phase. Please, let me know if you have any question**

# ssl-simplifier project

This project is expected to read `SSL Debug` log from JBoss EAP or based log files.

Also, this project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

# Running

If you want to run this project, you'll need the following:

* Java 11+
* Maven 3.6+

Run the following command to compile the project

```
./mvnw clean install
```

Now, running the `jar` **target/ssl-simplifier-1.0.0-SNAPSHOT-runner.jar** with `--help` parameter, you'll see:

```
$ java -jar target/ssl-simplifier-1.0.0-SNAPSHOT-runner.jar --help

__  ____  __  _____   ___  __ ____  ______ 
 --/ __ \/ / / / _ | / _ \/ //_/ / / / __/ 
 -/ /_/ / /_/ / __ |/ , _/ ,< / /_/ /\ \   
--\___\_\____/_/ |_/_/|_/_/|_|\____/___/   
2020-11-05 13:41:42,065 INFO  [io.quarkus] (main) ssl-simplifier 1.0.0-SNAPSHOT on JVM (powered by Quarkus 1.9.1.Final) started in 1.364s. Listening on: http://0.0.0.0:8080
2020-11-05 13:41:42,076 INFO  [io.quarkus] (main) Profile prod activated. 
2020-11-05 13:41:42,077 INFO  [io.quarkus] (main) Installed features: [agroal, cdi, hibernate-orm, hibernate-orm-panache, jdbc-h2, mutiny, narayana-jta, picocli, qute, resteasy-jackson, resteasy-jsonb, resteasy-qute, smallrye-context-propagation]

Usage: SSL Simplifier [-hV] [-if] [-iw] -f=<file> [-o=<output>]
  -f, --file=<file>       The file path with the SSL Handshake log
  -h, --help              Show this help message and exit.
      -if, --isfile       This option shows the report by json file at the
                            'output' parameter
      -iw, --isweb        This option shows the report by web page at http:
                            //localhost:8080/
  -o, --output=<output>   The output file path that we'll save the analyze file
  -V, --version           Print version information and exit.
2020-11-05 13:41:42,271 INFO  [io.quarkus] (main) ssl-simplifier stopped in 0.043s

```

**the parameter `-iw` or `--isweb` is not implemented, so far.**

Running the `jar` file with `-if` or `--isfile` the `--output` is required. The following is an example:

```
$ java -jar target/ssl-simplifier-1.0.0-SNAPSHOT-runner.jar -f /sslhandshake/server.log -o /sslhandshake/ -if
```

Refer the **ssls_report.json** file. 

for example:

~~~
{
  "javaInfos" : {
    "version" : "1.8.0_144",
    "name" : "Java Platform API Specification",
    "vendor" : "Oracle Corporation"
  },
  "allowUnsafeRegotiation" : false,
  "allowLegacyHelloMessage" : true,
  "isInitialHandshake" : true,
  "isSecureRegotiation" : false,
  "clientHelloInfo" : {
    "title" : "ClientHello, TLSv1.2",
    (...)
  }
  (...)
}
~~~
