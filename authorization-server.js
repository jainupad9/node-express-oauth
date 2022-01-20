const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	deleteAllKeys,
	containsAll,
	decodeAuthCredentials,
	timeout,
	randomString,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

/*
Your code here
*/
app.get("/authorize", (req, res) => {
	const query = req.query;
	const clientId = query.client_id;
	const scopes = query.scope.split(" ");
	const requestId = randomString();	

	if (!clients.hasOwnProperty(clientId)){
		res.status(401);
		return;
	}

	if (!containsAll(scopes, clients[clientId].scopes)){
		res.status(401);
		return;	
	}

	requests[requestId] = query;

	res.render("login", {
		"client": clients[clientId],
		"scope": scopes,
		requestId
	})
	res.status(200).end();
});

app.post("/approve", (req, res) => {
	const { userName, password, requestId } = req.body;
	const randomCode = randomString();

	if (!userName || !password || !users.hasOwnProperty(userName) || users[userName] !== password){
		res.status(401);
		return;
	}

	if (!requestId || !requests[requestId]){
		res.status(401);
		return;
	}

	const clientRequest = requests[requestId];
	delete requests[requestId];

	authorizationCodes[randomCode] = {
		userName,
		clientReq: clientRequest
	};

	const url = new URL(clientRequest.redirect_uri);
	url.searchParams.append("code", randomCode);
	url.searchParams.append("state", clientRequest.code);

	res.redirect(url);

	res.status(200);
});

app.post("/token", (req, res) => {
	if (!req.headers.authorization){
		res.status(401);
		return;
	}
	const {clientId, clientSecret} = decodeAuthCredentials(req.headers.authorization);

	if (!clients.hasOwnProperty(clientId) || clients[clientId].clientSecret !== clientSecret){
		res.status(401);
		return;
	}

	if (!req.body.code || !authorizationCodes[req.body.code]){
		res.status(401);
		return;
	}

	const { clientReq, userName } = authorizationCodes[req.body.code];
	delete authorizationCodes[req.body.code];

	const jwtString = jwt.sign(
		{
			userName,
			scope: clientReq.scope
		},
		config.privateKey,
		{
			algorithm: "RS256",
			expiresIn: 300,
			issuer: "http://localhost:" + config.port,
		}
	);

	return res.status(200).json({
		"access_token": jwtString,
		"token_type": "Bearer"
	});
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
