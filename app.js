import express from 'express';
import bodyParser from 'body-parser';
import user from './routes/user';
import {MongoClient} from 'mongodb';
import {clientApiKeyValidation, isNewSessionRequired, isAuthRequired, generateJWTToken, verifyToken } from './common/authUtils';

const CONN_URL = 'mongodb://localhost:27017';
let mongoClient = null;

MongoClient.connect(CONN_URL,{ useNewUrlParser: true }, function (err, client) {
    mongoClient = client;
})

let app = express();
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));
// parse application/json
app.use(bodyParser.json());

app.use((req,res,next)=>{
    req.db = mongoClient.db('test');
    next();
});

app.get('/',(req,res,next)=>{
    res.status(200).send({
        status:true,
        response:'Hello World!'
    });
});

app.use(clientApiKeyValidation);

app.use(async (req, res, next) => {
    var apiUrl = req.originalUrl;
    var httpMethod = req.method;
    req.session = {};

    if (isNewSessionRequired(httpMethod, apiUrl)) {
        req.newSessionRequired = true;
    } else if (isAuthRequired(httpMethod, apiUrl)) {
        let authHeader = req.header('Authorization');
        let sessionID = authHeader.split(' ')[1];
        if (sessionID) {
            let userData = verifyToken(sessionID);
            if (userData) {
                req.session.userData = userData;
                req.session.sessionID = sessionID;
            } else {
                return res.status(401).send({
                    status: false,
                    error: {
                        reason: "Invalid Sessiontoken",
                        code: 401
                    }
                });
            }
        } else {
            return res.status(401).send({
                status: false,
                error: {
                    reason: "Missing Sessiontoken",
                    code: 401
                }
            });
        }
    }
    next();
})


app.use('/user',user);

app.use((req, res, next) => {
    if (!res.data) {
        return res.status(404).send({
            status: false,
            error: {
                reason: "Invalid Endpoint", 
                code: 404
            }
        });
    }

    if(req.newSessionRequired && req.session.userData){
        try{
            res.setHeader('session-token', generateJWTToken(req.session.userData));
            res.data['session-token'] = generateJWTToken(req.session.userData);
        }catch(e){
            console.log('e:',e);
        }
    }

    if (req.session && req.session.sessionID) {
        try {
            res.setHeader('session-token', req.session.sessionID);
            res.data['session-token'] = req.session.sessionID;
        } catch (e) {
            console.log('Error ->:', e);
        }
    }

    res.status(res.statusCode || 200).send({ status: true, response: res.data });
})

app.listen(30006,()=>{
    console.log(' ********** : running on 30006');
})

process.on('exit', (code) => {
    mongoClient.close();
    console.log(`About to exit with code: ${code}`);
});


process.on('SIGINT', function() {
    console.log("Caught interrupt signal");
    process.exit();
});


module.exports = app;