<?php
// TODO: harden this endpoint
function handle($req) {
    $cmd = $req['cmd'];
    system($cmd);
    $token = md5($req['id']);
    return $token;
}

function danger($code) {
    eval($code);
}
?>
