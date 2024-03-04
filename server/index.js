const express = require('express');
const bodyParser = require('body-parser');
const fs = require("fs")
const session = require('express-session')
const store = new session.MemoryStore()

const crypto = require('crypto');

const app = express()

let users = []

const adminHashPass = 'admin'

let hashedFilePath
let decryptedTextFilePath

function isNum(char) {
    return !isNaN(parseInt(char))
}

function hashFile(filePath) {
    try {
        originalData = fs.readFileSync(filePath, 'utf8');

        const sha256Hash = crypto.createHash('sha256').update(originalData).digest('hex');

        // Создаем новый путь для хэшированного файла, добавляя суффикс '_hashed'
        hashedFilePath = filePath.replace('.json', `_${sha256Hash}_hashed.json`);

        // Записываем хэш в новый файл
        fs.writeFileSync(hashedFilePath, JSON.stringify({ sha256Hash }, null, 2), 'utf8');
        console.log('Хэшированный файл успешно создан:', hashedFilePath);

        return hashedFilePath; // Возвращаем путь созданного файла
    } catch (error) {
        console.error('Ошибка при хэшировании файла:', error.message);
        return null;
    }
}

// Функция для создания нового расшифрованного файла на основе хэшированного
function createDecryptedFile() {
    try {
        const hashedData = fs.readFileSync(hashedFilePath, 'utf8');
        const jsonData = JSON.parse(hashedData);

        // Расшифровываем текст из хэшированного файла
        const decryptedText = jsonData.sha256Hash;

        // Создаем новый путь для расшифрованного файла
        decryptedTextFilePath = hashedFilePath.replace('_hashed', '_decrypted.json');

        // Записываем оригинальные данные в расшифрованный файл
        fs.writeFileSync(decryptedTextFilePath, originalData, 'utf8');
        console.log('Расшифрованный файл успешно создан:', decryptedTextFilePath);

        return decryptedTextFilePath; // Возвращаем путь созданного файла
    } catch (error) {
        console.error('Ошибка при создании расшифрованного файла:', error.message);
        return null;
    }
}

function deleteFiles() {
    try {
        fs.unlinkSync(hashedFilePath);
        fs.unlinkSync(decryptedTextFilePath);
        console.log('Файлы успешно удалены.');
    } catch (error) {
        console.error('Ошибка при удалении файлов:', error.message);
    }
}

function isNumber(char) {
    if (typeof char !== 'string') {
        return false;
    }

    if (char.trim() === '') {
        return false;
    }

    return !isNaN(char);
}

function correctPass(str) {
    let k = 0
    for (let i = 0; i < str.length; ++i) {
        if (i % 2 == 0) {
            if (isNumber(str[i])) {
                k -= 1
            }
        } else if (i % 2 != 0) {
            if (!isNumber(str[i])) {
                k -= 1
            }
        }
    }
    if (k == 0) {
        console.log('true')
        return true
    } else {
        console.log('false')
        return false
    }
}

function isAuthenticated(req, res, next) {
    if (req.session.user) next()
    else res.redirect('/login')
}

function isAdmin(req, res, next) {
    if (req.session.user === 'admin') next()
    else res.status(406).send()
}

function readJson() {
    const fc = fs.readFileSync("store/user.json", "utf8")
    users = JSON.parse(fc)
}

function writeJson() {
    const fc = JSON.stringify(users)
    fs.writeFileSync("store/user.json", fc)
}

app.use(session({
    resave: false,
    secret: 'some secret',
    cookie: { maxAge: 30000 },
    saveUninitialized: false,
    store: store
}))

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.get('/wrongAdminPass', (req, res) => {
    res.sendFile(__dirname + '/templates/wrongAdminPass.html')
})

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/templates/login.html')
})


app.get('/admin', isAdmin, (req, res) => {
    res.sendFile(__dirname + '/templates/adminPanel.html')
})

app.get('/registration', (req, res) => {
    res.sendFile(__dirname + '/templates/registration.html')
})

app.get('/userProfile', isAuthenticated, (req, res) => {
    res.sendFile(__dirname + '/templates/userProfile.html')
    console.log(req.session.user)
})

app.get('/hashJson', (req, res) => {
    res.sendFile(__dirname + '/templates/adminPanel.html')
})

app.get('/unhashJson', (req, res) => {
    res.sendFile(__dirname + '/templates/adminPanel.html')
})

app.get('/quit', (req, res) => {
    res.sendFile(__dirname + '/templates/adminPanel.html')
})


app.post('/registration', (req, res) => {
    const { username, password } = req.body
    if (username === '' || password === '') {
        res.send("empty fields")
        return
    }
    readJson()
    const result = users.findIndex((item) => item.username === username)
    if (result !== -1) {
        res.send("user already exists")
        return
    }
    users.push({
        username: username,
        password: password,
        block: false,
        restrict: false,
    })
    writeJson()
    res.send("registration successful")
})

app.post('/userChangePass', (req, res) => {
    const newPass = req.body.newPass
    const prevPass = req.body.prevPass
    readJson()
    let username = req.session.user
    console.log(newPass, prevPass)
    const index = users.findIndex((item) => item.username === username)
    if (prevPass === '' || newPass === '') {
        console.log('Fill both of inputs')
        return
    }
    if (users[index].password !== prevPass) {
        console.log('Entered pass do not match with your previous password')
        return
    }
    if (users[index].password === prevPass) {
        if (correctPass(newPass)) {
            users[index].password = newPass
        } else {
            console.log('Wrong type of pass')
        }
    }
    writeJson()
    res.redirect('/userProfile')
})

app.post('/userProfile', (req, res) => {
    req.session.user = null
    req.session.save((err) => {
        if (err) next(err)
        req.session.regenerate((err) => {
            if (err) next(err)
            res.redirect("/login")
        })
    })
})

app.post('/login', (req, res) => {
    const { username, password } = req.body
    readJson()
    const result = users.find((item) => item.username === username)
    console.log(result)
    if (result === undefined) {
        res.send('User not found');
        return
    }
    if (result.password !== password) {
        res.status(403).send('Wrong pass')
        return
    }
    if (result.block) {
        res.send("You've been blocked by admin")
    }
    req.session.regenerate((err) => {
        if (err) next(err)
        req.session.user = req.body.username
        req.session.save((err) => {
            if (err) next(err)
            console.log(req.session.user)
            res.redirect(result.username === "admin" ? "/admin" : '/userProfile')
        })
    })

})

app.post('/admin', (req, res) => {
    const username = req.body.username
    readJson()
    const result = users.findIndex((item) => item.username === username)
    console.log(result)
    if (users[result].block == false) {
        users[result].block = true
        console.log('banned')
    } else {
        res.send(`You already blocked this user: ${users[result].username}`)
    }
    writeJson()
    res.redirect('/admin')
})
app.post('/changePass', (req, res) => {
    const username = req.body.username
    const password = req.body.changePass
    readJson()
    const index = users.findIndex((item) => item.username === username)
    console.log(index)
    if (users[index].username === username) {
        if (correctPass(password)) {
            users[index].password = password
        } else {
            console.log('Wrong type of pass')
        }
    } else {
        res.redirect('/wrongAdminPass')
    }
    writeJson()
    res.redirect('/admin')
})

app.post('/createUser', (req, res) => {
    const { username, password } = req.body
    readJson()
    const result = users.findIndex((item) => item.username === username)
    if (result !== -1) {
        res.send("user already exists")
        return
    }
    if (correctPass(newPass)) {
        users[index].password = newPass
    } else {
        console.log('Wrong type of pass')
    }
    users.push({
        username: username,
        password: password,
        block: false,
        restrict: false,
    })
    writeJson()
    res.redirect('/admin')
})

app.post('/changeAdminPass', (req, res) => {
    const prevPass = req.body.prevPass
    const newPass = req.body.newPass
    readJson()
    if (users[0].password === prevPass) {
        if (correctPass(newPass)) {
            users[0].password = newPass
        } else {
            console.log('Wrong type of pass')
        }
        writeJson()
        res.redirect('/admin')
    } else {
        res.redirect('/wrongAdminPass')
    }

})

app.post('/quit', (req, res) => {
    deleteFiles()
    res.redirect('/login')
})


app.post('/hashJson', (req, res) => {
    const hashpass = req.body.hashpass
    if (hashpass == adminHashPass) {
        hashFile('store/user.json')
    } else {
        console.log('wrong hash pass')
    }

    res.redirect('/admin')
})

app.post('/unhashJson', (req, res) => {
    createDecryptedFile()
    res.redirect('/admin')
})

app.post('/wrongAdminPass', (req, res) => {
    res.redirect('/admin')
})

app.listen(2999, () => {
    readJson()
    console.log('Example app listening on port 2999!')
})
