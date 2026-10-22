<?php
// Benign baseline: a normal upload handler (optionally with upload progress).
session_start();
printf("files=%d fields=%d\n", count($_FILES, COUNT_RECURSIVE), count($_POST));
