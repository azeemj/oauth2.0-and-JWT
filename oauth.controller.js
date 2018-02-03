import jwt from 'jsonwebtoken';
        import httpStatus from 'http-status';
        import assert from 'assert';
        import bcrypt from 'bcryptjs';
        import OauthServer from '../../classes/OauthServer.class';
        var oauth = new OauthServer();
        
        
        
        /**
         * Register the client
         * @param {string} device_id
         * @return {json}array 
         */

                function registerClient(req, res, next){
                if (!req.headers.device_id)
                        return res.json({success: 0, content: {message: "Please send the device token."}});
                        let device_id = req.headers.device_id;
                        oauth.createClients(device_id, function(client){

                        if (client){
                        return res.json({success: 1, content: {message: "Clients inofrmarion", result:{clientSecret:client.clientSecret,
                                client_id:client.client_id}}});
                        } else{
                        return res.json({success: 0, content: {message: "Clients registration failed."}});
                        }
                        });
                }



        /**
         * login process with JWT token based OAUTH2.0 in order to protect the API access 
         * @param {string} device_id
         * @param string client_id
         * @param {string} password_login
         * @param String email_login
         * @return {json}array ,Authorization code 
         */
        function login (req, res, next){


        if (!req.headers.device_id)
                return res.json({success: 0, content: {message: "Please send the device token."}});
                if (!req.headers.client_id)
                return res.json({success: 0, content: {message: "Please send the API key."}});
                if (!req.body.email_login)
                return res.json({success: 0, content: {message: "Please send the user email."}});
                if (!req.body.password_login)
                return res.json({success: 0, content: {message: "Please send the password."}});
                //check user name and password
                let userName = req.body.email_login.toLowerCase();
                let pwd = req.body.password_login;
                let client_id = req.headers.client_id;
                let device_id = req.headers.device_id;
                oauth.validateClientId(client_id, function(result){console.log(result);
                        if (!result){
                return res.json({success: 0, content: {message: "Wrong clientId key"}});
                } else{

                oauth.validateLoginCredentials(userName, pwd, function(result2){

                if (!result2){
                return res.json({success: 0, content: {message: "Wrong username/password"}});
                } else{
                //if login success then generate access code and return it to the client 
                oauth.getAccessCode(client_id, device_id, function(result3){console.log("code" + result3)
                        if (result3){//generate token
                return res.json({success: 1, content: {message: "generated Authorizationcode", result:result3.authorization_code}});
                } else{

                oauth.createAccessCode(result2._id, device_id, client_id, function(code){

                if (code){
                return res.json({success: 1, content: {message: "generated Authorizationcode", result:code.authorization_code}});
                } else{
                return res.json({success: 0, content: {message: "Wrong on generating Authorizationcode"}});
                }
                });
                }
                })




                }
                })

                }

                })



        }



        /**
         * login process with JWT token based OAUTH2.0 in order to protect the API access 
         * @param {string} device_id
         * @param string access_code
         * @param {string} client_id
         * @return {json}array ,Accesstoken
         */
        function requestAccessToken(req, res, next){
        if (!req.body.access_code)
                return res.json({success: 0, content: {message: "Please send the access code."}});
                if (!req.headers.client_id)
                return res.json({success: 0, content: {message: "Please send the API key."}});
                let device_id = req.headers.device_id;
                let client_id = req.headers.client_id;
                let access_code = req.body.access_code;
                oauth.getAccessCode(client_id, device_id, function(code){
                let user_id = code.user_id;
                        if (code.authorization_code == access_code)
                {
                oauth.getAccessToken(user_id, device_id, function(gettoken){ console.log("gettoken" + gettoken);
                        oauth.getUserInfo(user_id, function(userinfo){
                        if (gettoken){console.log(gettoken);
                                return res.json({success: 1, content:
                                {message: "generated token",
                                        result:{username:userinfo.username, firstName:userinfo.firstName, access_token:gettoken.access_token}}});
                        } else{
                        oauth.createAccessToken(user_id, device_id, client_id, function(create_token){

                        return res.json({success: 1, content:
                        {message: "generated token",
                                result:{username:userinfo.username, firstName:userinfo.firstName, access_token:create_token.access_token}}});
                        });
                        }

                        })

                })
                } else{

                return res.json({success: 0, content: {message: "Wrong on Authorizationcode"}});
                }


                })




        }













        export default {

        login,
                requestAccessToken,
                tokenTest,
                registerClient,
                signup,
                logOut
        };
