// implied eval: string argument is eval'd
setTimeout("doStuff()", 100);

// a function reference is fine (must NOT be flagged)
setInterval(() => tick(), 200);

function load() {
  try {
    risky();
  } catch (e) {}
}

const apiSecret = "s3cr3t-token-value";
