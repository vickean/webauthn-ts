import path from 'path'
import { router as AuthenticationRouter } from './authentication/router'

import express from 'express'
import dotenv from 'dotenv'
import cookies from 'cookie-parser'

import * as fs from 'fs'
import * as https from 'https'

const key = fs.readFileSync(
    path.join(__dirname, '..', './src/ssl/sora.dev.ringgitplus.com.key')
)
const cert = fs.readFileSync(
    path.join(__dirname, '..', './src/ssl/sora.dev.ringgitplus.com.crt')
)

const app = express()
dotenv.config()

app.use(cookies())
app.use(express.static(path.join(__dirname, '..', 'pages')))
app.use(
    '/.well-known',
    express.static(path.join(__dirname, '..', '.well-known'))
)

app.use('/authentication', (req, res, next) => {
    AuthenticationRouter(req, res, next)
})

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'pages', 'home.html'))
})

const server = https.createServer({ key, cert }, app)

server.listen(process.env.PORT || 4430, () => {
    console.log('Server is running on port 4430!')
})

// app.listen(process.env.PORT || 4430, () => {
//     console.log('Server is running on port 4430!')
// })
