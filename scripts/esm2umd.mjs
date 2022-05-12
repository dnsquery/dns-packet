#!/usr/bin/env node
import fs from 'fs'
import esm2umd from 'esm2umd'

async function toUMD (dirname) {
  const files = await fs.promises.readdir(dirname)
  for (const file of files.filter(file => file.endsWith('.mjs'))) {
    const name = file.replace(/\.mjs$/, '')
    const source = new URL(file, dirname)
    const target = new URL(`${name}.cjs`, dirname)
    const esmFile = await fs.promises.readFile(source)
    const data = esm2umd(process.argv[2], esmFile, { importInterop: 'node' })
      .replace(/dns-packet/g, '.')
      .replace(/.js/g, '.cjs')
    await fs.promises.writeFile(target, data)
  }
}

;(async () => {
  await toUMD(new URL('..', import.meta.url))
  await toUMD(new URL('../examples/', import.meta.url))
})()
  .catch(err => {
    console.error(err.stack)
    process.exit(1)
  })
