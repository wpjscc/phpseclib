<?php

/**
 * Interactive SSH shell example (async I/O + React loop).
 *
 * Use SSH2::READ_NEXT for streaming output; default read('') waits for a prompt
 * match and interacts badly with empty $expect (long timeouts per packet).
 */

require_once __DIR__ . '/../vendor/autoload.php';

use phpseclib4\Net\SSH2;
use phpseclib4\Crypt\PublicKeyLoader;
use function React\Async\async;
use React\EventLoop\Loop;

/**
 * PTY size must match this terminal or remote programs (ls, vim, etc.) will format for the wrong width
 * and wrapped output will look scrambled.
 *
 * @phpstan-return array{0: positive-int, 1: positive-int} [rows, columns]
 */
function local_terminal_size(): array
{
    $envCols = getenv('COLUMNS');
    $envLines = getenv('LINES');
    if (is_string($envCols) && is_string($envLines) && ctype_digit($envCols) && ctype_digit($envLines)) {
        $rows = max(1, (int) $envLines);
        $cols = max(1, (int) $envCols);

        return [$rows, $cols];
    }

    if (function_exists('shell_exec')) {
        $stty = shell_exec('stty size 2>/dev/null');
        if (is_string($stty) && preg_match('/^(\d+)\s+(\d+)/', trim($stty), $m)) {
            $rows = max(1, (int) $m[1]);
            $cols = max(1, (int) $m[2]);

            return [$rows, $cols];
        }
    }

    return [24, 80];
}

/**
 * Line mode (fgets) makes arrow keys produce visible escape garbage (e.g. ^[OA); remote needs raw key bytes.
 * Disable local echo and canonical mode so fread() forwards sequences to SSH and the PTY echoes.
 *
 * @return string|null saved stty state for restore, or null if not a TTY / stty missing
 */
function begin_stdin_pass_through(): ?string
{
    if (!function_exists('stream_isatty') || !stream_isatty(STDIN)) {
        return null;
    }
    $saved = shell_exec('stty -g </dev/tty 2>/dev/null');
    if (!is_string($saved) || $saved === '') {
        return null;
    }
    $saved = trim($saved);
    shell_exec('stty -icanon -echo min 1 time 0 </dev/tty 2>/dev/null');

    return $saved;
}

function end_stdin_pass_through(?string $saved): void
{
    if ($saved === null || $saved === '') {
        shell_exec('stty sane </dev/tty 2>/dev/null');

        return;
    }
    shell_exec('stty ' . $saved . ' </dev/tty 2>/dev/null');
}

async(function (): void {
    $key = PublicKeyLoader::load(file_get_contents('/root/.ssh/id_rsa'));

    $ssh = new SSH2(host: 'localhost', useAsyncIo: true);
    // Interactive: avoid multi-second idle waits when using READ_NEXT with sparse output.
    $ssh->setTimeout(2);

    if (!$ssh->login('root', $key)) {
        throw new \Exception('Login failed');
    }

    [$rows, $cols] = local_terminal_size();
    $ssh->setWindowSize(columns: $cols, rows: $rows);

    $sttySaved = begin_stdin_pass_through();
    register_shutdown_function(static function () use ($sttySaved): void {
        end_stdin_pass_through($sttySaved);
    });

    stream_set_blocking(STDIN, false);

    Loop::addReadStream(STDIN, static function () use ($ssh): void {
        $chunk = fread(STDIN, 8192);
        if ($chunk === false || $chunk === '') {
            return;
        }
        $ssh->write($chunk);
    });

    while (true) {
        $response = $ssh->read('', SSH2::READ_NEXT);
        if ($response === false) {
            continue;
        }
        if ($response === true) {
            // Window adjust, channel handshake bookkeeping, etc.
            continue;
        }
        if ($response !== '') {
            echo $response;
            flush();
        }
    }
})();

Loop::run();

