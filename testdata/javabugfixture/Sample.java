class Sample {
    boolean compare(String s) {
        // == compares references, not contents
        return s == "expected";
    }

    void swallow(String s) {
        try {
            process(s);
        } catch (NullPointerException e) {
            log("ignored");
        }
    }

    // Hard-coded credential: should be loaded from the environment.
    private static final String apiSecret = "s3cr3t-value";

    void process(String s) {}
    void log(String s) {}
}
