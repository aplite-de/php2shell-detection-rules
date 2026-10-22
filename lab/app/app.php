<?php
// FPM path: a decoder reachable from request data after startup, like
// WordPress maybe_unserialize() or a session handler.
session_start();

$data = $_POST['data'] ?? '';
if (($_GET['op'] ?? '') === 'session_decode') {
    session_decode($data);
} else {
    @unserialize($data, ['allowed_classes' => false]);
}
echo "ok\n";
