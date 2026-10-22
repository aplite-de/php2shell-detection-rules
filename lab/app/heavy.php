<?php
// Benign baseline: an application bug that exhausts memory_limit inside a script
// (fatal reports a real file and line, not "Unknown on line 0").
$a = [];
for (;;) {
    $a[] = str_repeat('x', 1024 * 1024);
}
