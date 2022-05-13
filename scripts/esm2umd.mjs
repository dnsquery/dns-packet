#!/usr/bin/env node
import fs from 'fs'
import esm2umd from 'esm2umd'
import process from 'process'
import { pathToFileURL } from 'url'
import { sep, join } from 'path'

async function toUMD (dirname, packageName, base) {
  const files = await fs.promises.readdir(dirname)
  const replaceRegexp = new RegExp(`(require\\s*\\(\\s*["'])${packageName}(\\/(.+)\\.js)?(["']\\s*\\))`, 'g')
  for (const file of files) {
    const source = new URL(file, dirname)
    const stat = await fs.promises.stat(source)
    if (stat.isDirectory()) {
      if (file === 'node_modules' || file.startsWith('.')) {
        continue
      }
      await toUMD(new URL(source.href + sep), packageName, base === '.' ? '..' : base + sep + '..')
    }
    if (!file.endsWith('.mjs')) {
      continue
    }
    if (source.href === import.meta.url) {
      continue
    }
    const name = file.replace(/\.mjs$/, '')
    const target = new URL(`${name}.cjs`, dirname)
    const esmFile = await fs.promises.readFile(source)
    let data = esm2umd(process.argv[2], esmFile, { importInterop: 'node' })
    data = data.replace(
      replaceRegexp,
      (found, prefix, pth, name, suffix) => {
        return `${prefix}${pth ? `${base}/${name}.cjs` : base}${suffix}`
      }
    )
    await fs.promises.writeFile(target, data)
  }
}

;(async () => {
  const { name } = JSON.parse(await fs.promises.readFile(join(process.cwd(), 'package.json'), 'utf8'))
  await toUMD(pathToFileURL(process.cwd() + sep), name, '.')
})()
  .catch(err => {
    console.error(err.stack)
    process.exit(1)
  })
