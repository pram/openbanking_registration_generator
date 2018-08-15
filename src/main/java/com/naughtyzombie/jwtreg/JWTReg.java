package com.naughtyzombie.jwtreg;

import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import java.io.File;

@CommandLine.Command(name = "jwtreg", mixinStandardHelpOptions = true, version = "JWT Registration App")
public class JWTReg implements Runnable {

    @Option(names = {"-i","--software-statement-id"}, arity = "1", description = "Software Statement Id")
    private String ssId;

    @Option(names = {"-s", "--software-statement"}, arity = "1", description = "Software Statement")
    private File softwareStatementFile;

    @Option(names = {"-p", "--private-key"}, arity = "1", description = "Private RSA Key")
    private File privateKeyFile;

    @Option(names = {"-k","--key-id"}, arity = "1", description = "Key Id")
    private String kid;


    public void run() {

    }

    public static void main(String[] args) {
        CommandLine.run(new JWTReg(), System.out, args);
    }
}
