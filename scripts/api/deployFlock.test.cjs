const assert = require('node:assert/strict')
const { spawn, spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const handoff = path.resolve(__dirname, '../instant-win')
const deploy = path.join(handoff, 'deploy-aws.sh')

function makeTree() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'iw-deploy-'))
    const app = path.join(root, 'app')
    fs.mkdirSync(path.join(app, 'src'), { recursive: true })
    fs.writeFileSync(path.join(app, 'src', 'index.ts'), 'export {}\n')
    return {
        root,
        app,
        lock: path.join(root, 'login.lock'),
        backup: path.join(root, 'backups'),
        staging: path.join(root, 'stage')
    }
}

function envFor(tree) {
    return {
        ...process.env,
        TZ: 'Asia/Shanghai',
        APP_ROOT: tree.app,
        LOCK_FILE: tree.lock,
        BACKUP_ROOT: tree.backup,
        STAGING_ROOT: tree.staging,
        INSTANT_WIN_DEPLOY_SKIP_MUTATION: '1',
        NODE_BIN: process.execPath,
        NPM_BIN: process.execPath
    }
}

test('deploy exits 75 when the same flock is already held', () => {
    const tree = makeTree()
    const holder = spawn('bash', ['-lc', `exec 9>>"$1"; flock -n 9 && sleep 20`, 'holder', tree.lock], {
        stdio: 'ignore'
    })
    try {
        spawnSync('bash', ['-lc', 'for i in $(seq 1 50); do [ -f "$1" ] && python3 -c "import os,sys; os.sysconf(\'SC_OPEN_MAX\')" >/dev/null; sleep 0.05; flock -n 8 8>>"$1" && exit 1; fuser "$1" >/dev/null 2>&1 && exit 0; done; exit 0', 'wait', tree.lock], { encoding: 'utf8' })
        // Give the holder a moment to acquire the lock
        const wait = spawnSync('bash', ['-lc', `for i in $(seq 1 40); do if flock -n 8 8>>"$1"; then sleep 0.05; else exit 0; fi; done; exit 1`, 'waitlock', tree.lock])
        assert.equal(wait.status, 0, 'holder should own the lock before deploy')
        const result = spawnSync('bash', [deploy], { env: envFor(tree), encoding: 'utf8' })
        assert.equal(result.status, 75, result.stdout + result.stderr)
        assert.match(result.stderr || result.stdout, /lock is held/)
    } finally {
        try { process.kill(holder.pid, 'SIGTERM') } catch {}
        fs.rmSync(tree.root, { recursive: true, force: true })
    }
})

test('deploy holds the same flock for the whole skip-mutation window', async () => {
    const tree = makeTree()
    const env = { ...envFor(tree), INSTANT_WIN_DEPLOY_HOLD_SECONDS: '2' }
    const child = spawn('bash', [deploy], { env, encoding: 'utf8' })
    const started = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('deploy did not acquire lock')), 4000)
        child.stdout.on('data', chunk => {
            const text = String(chunk)
            if (text.includes('LOCK_HELD')) {
                clearTimeout(timer)
                resolve(true)
            }
        })
        child.stderr.on('data', chunk => process.stderr.write(chunk))
        child.on('exit', code => {
            if (code && code !== 0) {
                clearTimeout(timer)
                reject(new Error('deploy exited early: ' + code))
            }
        })
    })
    assert.equal(started, true)
    const competed = spawnSync('bash', ['-lc', 'flock -n 8 8>>"$1"', 'compete', tree.lock])
    assert.notEqual(competed.status, 0)
    const exitCode = await new Promise(resolve => child.on('exit', resolve))
    assert.equal(exitCode, 0)
    const after = spawnSync('bash', ['-lc', 'flock -n 8 8>>"$1" && echo OK', 'after', tree.lock], { encoding: 'utf8' })
    assert.equal(after.status, 0)
    assert.match(after.stdout, /OK/)
    fs.rmSync(tree.root, { recursive: true, force: true })
})

test('deploy inherits an already-held lock FD and does not self-deadlock', () => {
    const tree = makeTree()
    const script = `
      set -euo pipefail
      exec 9>>"$LOCK_FILE"
      flock -n 9
      export INSTANT_WIN_LOCK_FD=9
      bash "$DEPLOY"
    `
    const result = spawnSync('bash', ['-lc', script, 'inherit'], {
        env: { ...envFor(tree), DEPLOY: deploy, LOCK_FILE: tree.lock },
        encoding: 'utf8'
    })
    assert.equal(result.status, 0, result.stdout + result.stderr)
    assert.match(result.stdout, /LOCK_INHERITED/)
    fs.rmSync(tree.root, { recursive: true, force: true })
})
