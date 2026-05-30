using System;
using System.Security.Cryptography;
using System.Diagnostics;

class Sample {
    void Handle(string cmd) {
        try { Work(); } catch { }
        var hash = MD5.Create();
        Process.Start(cmd);
    }
    void Work() { }
}
