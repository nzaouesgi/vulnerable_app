const express = require('express')
const mongoose = require('mongoose')
const sqlite3 = require('sqlite3')

const sqlDb = new sqlite3.Database(':memory:');

const Model = mongoose.model('Model', new mongoose.Schema({
    name: {
        type: String,
        required: true
    }
}));

(async () => {

    await mongoose.connect(`mongodb://127.0.0.1:27017/vulnerableapp`, {
        useNewUrlParser: true,
        bufferCommands: false,
        useUnifiedTopology: true,
        user: 'vulnerableapp',
        pass: 'vulnerableapp',
    })

    mongoose.connection.on('error', console.error)
    mongoose.connection.on('disconnected', console.error)
    mongoose.connection.on('reconnected', console.info)

    const testModel = new Model({ name: '<script>alert(1)</script>' })

    await testModel.save()

    const app = express()

    const html = (param) => `<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>${param}</body></html>`

    app.use((req,res,next) => {
        res.type('html')
        next()
    })

    // XSS ON API ENDPOINT
    app.get('/xss/api', async (req, res, next) => {
        const model = await Model.findOne()
        res.end(JSON.stringify(model))
    })

    // REFLECTED XSS
    app.get("/xss/reflected", (req, res, next) => {
        res.end(html(req.query.param))
    })

    // STORED XSS
    app.get("/xss/stored", async (req, res, next) => {
        const model = await Model.findOne()
        res.end(html(model.name))
    })

    // DOM BASED XSS
    app.get('/xss/dombased', (req, res, next) => {

        res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"></head><body><script>` +

            `fetch('https://jsonplaceholder.typicode.com/todos/1').then(response => response.json()).then(json => { document.body.innerHTML = json.title; })` +

            `</script></body></html>`)
    })

    // OPEN REDIRECT
    app.get('/openredirect', (req, res, next) => { req.session = {}; next(); }, (req, res, next) => {

        if (!req.session.user){
            res.location('/login')
            res.status(302)
        }

        res.end(`Secret area.`)
    })

    // NOSQLi
    app.post('/nosqli', express.json(), async (req, res, next) => {

        const models = await Model.find(req.body)

        res.end(JSON.stringify(models))
    })

    // SQLi
    app.get('/sqli', async (req, res, next) => {

        const sql = `SELECT * FROM users WHERE id = ${req.query.id}`

        sqlDb.get(sql, (err, row) => {
            res.end(row)
        })
    })

    app.listen(3000, () => console.log('listening'))

})()

.catch(console.error)