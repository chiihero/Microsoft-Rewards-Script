const assert = require('node:assert/strict')
const test = require('node:test')
require('../../node_modules/ts-node/register/transpile-only.js')
const ReactFunc = require('../../src/browser/ReactFunc.ts').default

// 2026-11-17 国区浏览器抓包：dashboard 的 Next-Router-State-Tree 原样编码
const BROWSER_DASHBOARD_TREE =
    '["",{"children":["(nav)",{"children":["dashboard",{"children":["__PAGE__",{},null,null,0]},null,null,0]},null,null,0]},null,null,16]'

function createReactFunc() {
    return new ReactFunc({})
}

test('pageRouterStateTree matches the browser-captured dashboard tree', () => {
    const actual = decodeURIComponent(createReactFunc().pageRouterStateTree('dashboard'))
    assert.equal(actual, BROWSER_DASHBOARD_TREE)
})

test('pageRouterStateTree keeps the requested segment', () => {
    const tree = JSON.parse(decodeURIComponent(createReactFunc().pageRouterStateTree('earn')))
    assert.equal(tree[1].children[1].children[0], 'earn')
})

test('legacy routerStateTree stays on the PAGE/4096 shape used by other callers', () => {
    const actual = decodeURIComponent(createReactFunc().routerStateTree('earn'))
    assert.match(actual, /"PAGE"/)
    assert.match(actual, /4096/)
})
