
import User from '../models/testuser.model';
        import Client from '../models/testclient.model';
        import Token from '../models/testoauthaccesstokens.model';
        import AccessCode from '../models/testoauthauthorizationcodes.model';
        var jwt = require('jsonwebtoken');
        import bcrypt from 'bcryptjs';
        export default class OauthServer{

        OauthServer(){

          
        }



        /**
         * genrating authorization code
         * @param {string} device_id
         * @param string client_id
         * @param {string} user_id
         * @return {json}array ,Authorization code 
         */
        createAccessCode(user_id, device_id, client_id, callback){
        let con_cat = user_id + 'test' + device_id;
                var code = jwt.sign(con_cat, 'test');
                let accessCode = new AccessCode({
                'client_id': client_id, "authorization_code": code, "device_id": device_id, 'user_id': user_id
                });
                accessCode.save(function (err, row) {
                if (err){
                callback(false);
                } else{
                callback(row);
                }

                //}
                });
        }

        /**
         * returning Authorization code
         * @param {string} device_id
         * @param string client_id
         * @return {json}array ,Authorization code 
         */
        getAccessCode(client_id, device_id, callback){
        AccessCode.findOne({'client_id': client_id, "device_id": device_id}, function(err, obj){console.log(obj);
                if (obj){
        callback(obj);
        } else{
        callback(false);
        }
        })

        }


        /**
         * genrating AccessToken
         * @param {string} device_id
         * @param string client_id
         * @param {string} user_id
         * @return {json}array ,AccessToken
         */
        createAccessToken(user_id, device_id, client_id, callback){
        var con_cat = '';
                con_cat = user_id + '' + device_id + "";
                let tok = jwt.sign(con_cat, 'ilovescotchy');
                let accessToken = new Token({
                'client_id': client_id, "access_token": tok, "device_id": device_id, 'user_id': user_id
                });
                accessToken.save(function (err, row) {
                if (err){
                callback(false);
                } else{
                callback(row);
                }

                //}
                });
        }
        /**
         * returning AccessToken
         * @param {string} device_id
         * @param string client_id
         * @return {json}array ,Authorization code 
         */
        getAccessToken(user_id, device_id, callback){

        Token.findOne({$and:[{'user_id': user_id, "device_id": device_id}]}, function(err, obj){

        if (obj && obj != ""){console.log("test" + obj);
                callback(obj);
        } else{
        callback(false);
        }
        })
        }

        /**
         * validating  AccessToken
         * @param {string} device_id
         * @param string client_id
         * @return {json}array ,boolean 
         */
        validateToken(req, next, callback){

        let token = req.body.token || req.query.token || req.headers['token'] || req.headers['x-access-token'];
                //get last parameter
                let requested_url = req.path;
                let requested_url_array = requested_url.split('/');
                let lastsegment = requested_url_array[requested_url_array.length - 1];
                // decode token
                if (token) { console.log("one" + token);
                // verifies secret and checks exp
                jwt.verify(token, 'ilovescotchyscotch', function (err, decoded) {
                if (err) {
                console.log("token failed");
                        callback(false)
                } else {console.log("token passed");
                        // if everything is good, save to request for use in other routes
                        var client_id = req.body.client_id || req.query.client_id || req.headers['client_id'];
                        var device_id = req.body.device_id || req.query.device_id || req.headers['device_id'];
                        Token.count({$and: [{'access_token': token}, {'device_id': device_id}, {'client_id': client_id}]}, function (err, clientdata) {
                        if (clientdata == 0){
                        callback(false)
                        } else {
                        callback(true)
                        }
                        }
                        );
                }
                });
        } else {console.log(req.path);
                if (req.path == "/login" || req.path == "/request-token" || req.path == "/register-client" || req.path == "/signup"){
        next();
        } else{
        var err = new Error('Not Found');
                console.log("Not Found");
                callback(false)
        }
        }





        }


        /**
         * validating  ClientID
         * @param string client_id
         * @return {json}array ,boolean 
         */

        validateClientId(clientId, callback){
        Client.findOne({client_id: clientId}, function (err, client) {console.log(clientId);
                if (client) {
        callback(true)
        } else{
        callback(false)
        }
        });
        }


        /**
         * validating  logininformation
         * @param string userName
         * @param string password
         * @return {json}array ,boolean 
         */
        validateLoginCredentials(userName, pwd, callback){

        User.findOne()
                .select('username')
                .where('username').equals(userName)
                .exec(function(err, email) {
                if (email) {

                User.findOne({
                username: userName
                }, function(err, person) {
                bcrypt.compare(pwd, person.password, function(err, success) {
                if (success) {

                callback(person);
                } else {
                callback(false);
                }
                });
                }
                );
                } else {
                callback(false);
                }
                //if it is successed then create an authorization code 
                });
        }



        /**
         * getting user information
         * @param string user_id
         * @return {json}array ,boolean|object 
         */
        getUserInfo(user_id, callback){

        //  User.findOne({_id:user_id},function(obj){
        User.findOne({_id:user_id})
                .select('username lastName')

                .exec(function(err, obj) {
                if (obj){
                callback(obj);
                } else{
                callback(false);
                }
                });
        }


        /**
         * regisering clients
         * @param string device_id
         * @return {json}array ,boolean |pbject
         */
        createClients(device_id, callback){
        var con_cat = '';
                con_cat = device_id;
                let tok = jwt.sign(con_cat, 'ilovescotchy');
                let client = new Client({
                'client_id': tok, "clientSecret": tok + "" + device_id, "device_id": device_id
                });
                client.save(function (err, row) {
                if (err){
                callback(false);
                } else{
                callback(row);
                }

                //}
                });
        }








        }




}