'use strict';

const x509 = require('x509');

var { Gateway, Wallets } = require('fabric-network');
const path = require('path');
const FabricCAServices = require('fabric-ca-client');
const fs = require('fs');

const util = require('util');

const getCCP = async (org) => {
    let ccpPath;
    if (org == "Org1") {
        ccpPath = path.resolve(__dirname, '..', 'config', 'connection-org1.json');

    } else if (org == "Org2") {
        ccpPath = path.resolve(__dirname, '..', 'config', 'connection-org2.json');
    } else
        return null
    const ccpJSON = fs.readFileSync(ccpPath, 'utf8')
    const ccp = JSON.parse(ccpJSON);
    return ccp
}

const getCaUrl = async (org, ccp) => {
    let caURL;
    if (org == "Org1") {
        caURL = ccp.certificateAuthorities['ca.org1.example.com'].url;

    } else if (org == "Org2") {
        caURL = ccp.certificateAuthorities['ca.org2.example.com'].url;
    } else
        return null
    return caURL

}

const getWalletPath = async (org) => {
    let walletPath;
    if (org == "Org1") {
        walletPath = path.join(process.cwd(), 'org1-wallet');

    } else if (org == "Org2") {
        walletPath = path.join(process.cwd(), 'org2-wallet');
    } else
        return null
    return walletPath

}


const getAffiliation = async (org) => {
    return org == "Org1" ? 'org1.department1' : 'org2.department1'
}

const getRegisteredUser = async (username, userOrg,userType,password, isJson) => {
    let ccp = await getCCP(userOrg)

    const caURL = await getCaUrl(userOrg, ccp)
    const ca = new FabricCAServices(caURL);

    const walletPath = await getWalletPath(userOrg)
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);

    const userIdentity = await wallet.get(username);
    if (userIdentity) {
        console.log(`An identity for the user ${username} already exists in the wallet`);
        var response =  `An identity for the user ${username} already exists in the wallet`
        return response
    }

    // Check to see if we've already enrolled the admin user.
    let adminIdentity = await wallet.get('admin');
    if (!adminIdentity) {
        console.log('An identity for the admin user "admin" does not exist in the wallet');
        await enrollAdmin(userOrg, ccp);
        adminIdentity = await wallet.get('admin');
        console.log("Admin Enrolled Successfully")
    }

    // build a user object for authenticating with the CA
    const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
    const adminUser = await provider.getUserContext(adminIdentity, 'admin');
    let secret;
    try {
        // Register the user, enroll the user, and import the new identity into the wallet.
        secret = await ca.register({ affiliation: await getAffiliation(userOrg), enrollmentID: username, role: 'client', attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: password, ecert: true}]}, adminUser);
        // secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: email, role: 'client', attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: password, ecert: true}]}, adminUser);
        // const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: username, role: 'client', attrs: [{ name: 'role', value: 'approver', ecert: true }] }, adminUser);

    } catch (error) {
        return error.message
    }

    const enrollment = await ca.enroll({ enrollmentID: username, enrollmentSecret: secret,attr_reqs: [{  name: 'userType', optional: false }, {  name: 'password', optional: false }] });
    // const enrollment = await ca.enroll({ enrollmentID: username, enrollmentSecret: secret, attr_reqs: [{ name: 'role', optional: false }] });

    let x509Identity;
    if (userOrg == "Org1") {
        x509Identity = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: 'Org1MSP',
            type: 'X.509',
        };
    } else if (userOrg == "Org2") {
        x509Identity = {
            credentials: {
                certificate: enrollment.certificate,
                privateKey: enrollment.key.toBytes(),
            },
            mspId: 'Org2MSP',
            type: 'X.509',
        };
    }

    await wallet.put(username, x509Identity);
    console.log(`Successfully registered and enrolled admin user ${username} and imported it into the wallet`);
    const usercheck = await wallet.get(username);
    var issuer = x509.parseCert(usercheck.credentials.certificate);
    var jsn = issuer.extensions['1.2.3.4.5.6.7.8.1'];
    jsn = jsn.substring(2);
    jsn = (JSON.parse(jsn));
    

    console.log(`S-------------------- ${jsn.attrs.password} ---------------------`);
    var response = {
        success: true,
        message: username + ' enrolled Successfully',
    };
    return response
}

const updatePassword = async (username, userOrg,userType,password,newpassword) => {
    let ccp = await getCCP(userOrg)

    const caURL = await getCaUrl(userOrg, ccp)
    const ca = new FabricCAServices(caURL);

    const walletPath = await getWalletPath(userOrg)
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);
    console.log('out of looppppppppppppppppppppppppppppppp')
    const usercheck = await wallet.get(username);
    var issuer = x509.parseCert(usercheck.credentials.certificate);
    var jsn = issuer.extensions['1.2.3.4.5.6.7.8.1'];
    jsn = jsn.substring(2);
    jsn = (JSON.parse(jsn));
    console.log(`**************************${jsn.attrs.password} *********************`);
    if (jsn.attrs.password == password)
    {
        console.log("in looppppppppppppppppppppppppppppppppppppp")
        const adminIdentity = await wallet.get('admin');
        const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
        const adminUser = await provider.getUserContext(adminIdentity, 'admin');
        
    try {
        
        
        // Register the user, enroll the user, and import the new identity into the wallet.
        //secret = await ca.register({ affiliation: await getAffiliation(userOrg), enrollmentID: username, role: 'client', attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: password, ecert: true}]}, adminUser);
        const identityService = ca.newIdentityService();
        var theIdentityRequest = { enrollmentID: username, affiliation: await getAffiliation(userOrg), attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: newpassword, ecert: true}] };
        let response = await identityService.update(username, theIdentityRequest,adminUser);
        // secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: email, role: 'client', attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: password, ecert: true}]}, adminUser);
        // const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: username, role: 'client', attrs: [{ name: 'role', value: 'approver', ecert: true }] }, adminUser);

    } catch (error) {
        return error.message
    }
    const userIdentity = await wallet.get(username);
    const newAppUser = await provider.getUserContext(userIdentity, username);
    const newEnrollment = await ca.reenroll(newAppUser, [{  name: 'userType', optional: false }, {  name: 'password', optional: false }]);
    // const enrollment = await ca.enroll({ enrollmentID: username, enrollmentSecret: secret, attr_reqs: [{ name: 'role', optional: false }] });

    let x509Identity;
    if (userOrg == "Org1") {
        x509Identity = {
            credentials: {
                certificate: newEnrollment.certificate,
                privateKey: newEnrollment.key.toBytes(),
            },
            mspId: 'Org1MSP',
            type: 'X.509',
        };
    } else if (userOrg == "Org2") {
        x509Identity = {
            credentials: {
                certificate: newEnrollment.certificate,
                privateKey: newEnrollment.key.toBytes(),
            },
            mspId: 'Org2MSP',
            type: 'X.509',
        };
    }

    await wallet.put(username, x509Identity);
    console.log(`Successfully registered and enrolled admin user ${username} and imported it into the wallet`);
    const usercheck = await wallet.get(username);
    var issuer = x509.parseCert(usercheck.credentials.certificate);
    var jsn = issuer.extensions['1.2.3.4.5.6.7.8.1'];
    jsn = jsn.substring(2);
    jsn = (JSON.parse(jsn));
    

    console.log(`**************************${jsn.attrs.password} *********************`);
    return "password updated"
    }
    else{
        return "password doesnot match"
    }
}

// exports.updatePassword = async (email, newPassword, orgName) => {

//     try
//     {
//         let ccp = await getCCP(orgName); //getting ccp path for this users organization...
//         const caURL = await getCaUrl(orgName, ccp);
//         const ca = new FabricCAServices(caURL);

//         //Getting wallet path for orgName...
//         const walletPath = await getWalletPath(orgName);
//         const wallet = await Wallets.newFileSystemWallet(walletPath);
//         console.log(" ");
//         logger.info(`Wallet path: ${walletPath}`);

//         //getting this user from the wallet
//         const userIdentity = await wallet.get(email);
//         if (userIdentity) { //if found i.e. user is registered

//             logger.debug(`Email ${email} is registered and has an account.`);

//             if(email !== 'admin')
//             {
//                 //parsing certificate to get user type of this user stored in the certificate
//                 var issuer = x509.parseCert(userIdentity.credentials.certificate);
//                 var jsn = issuer.extensions['1.2.3.4.5.6.7.8.1'];
//                 jsn = jsn.substring(2);
//                 jsn = (JSON.parse(jsn));
//                 var userType = jsn.attrs.userType;

//                 const adminIdentity = await wallet.get('admin');
//                 const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
//                 const adminUser = await provider.getUserContext(adminIdentity, 'admin');

//                 //updating the password in user's identity
//                 const newAppUser = await provider.getUserContext(userIdentity, email);
//                 const identityService = ca.newIdentityService();
//                 var theIdentityRequest = { enrollmentID: email, affiliation: 'org1.department1', attrs: [{name: 'userType', value: userType, ecert: true},{name: 'password', value: newPassword, ecert: true}] };
//                 let response = await identityService.update(email, theIdentityRequest, adminUser);
//                 console.log("UserIdenity attributes: ", response.result.attrs);

//                 //Reenrolling the user to update its certificate
//                 const newEnrollment = await ca.reenroll(newAppUser, [{  name: 'userType', optional: false }, {  name: 'password', optional: false }]);
//                 const newX509Identity = {
//                         credentials: {
//                                 certificate: newEnrollment.certificate,
//                                 privateKey: newEnrollment.key.toBytes(),
//                         },
//                         mspId: 'Org1MSP',
//                         type: 'X.509',
//                 };
//                 await wallet.put(email, newX509Identity);

//                 logger.debug('Now updating the password length in database');
//                 var newPasswordLength = newPassword.length;
//                 var newPasswordDate = new Date().toString();

//                 //first getting user details from database
//                 var channelName = 'mychannel', chaincodeName = 'fabcar';

//                 //Create a new gateway for connecting to our peer node
//                 const gateway = new Gateway();
//                 await gateway.connect(ccp, {
//                     wallet, identity: email, discovery: { enabled: true, asLocalhost: true }
//                 });

//                 //Get the network (channel) our contract is deployed to.
//                 const network = await gateway.getNetwork(channelName);

//                 //Get the contract from the network.
//                 const contract = network.getContract(chaincodeName);

//                 //Getting User Details
//                 let details = await contract.evaluateTransaction("getQueryResultForQueryString", "{ \"selector\": { \"email\": \"" + email + "\" } }");

//                 details = JSON.parse(details.toString());
//                 var userId = details[0]['Key'];
//                 var name = details[0]['Record']['name'];
//                 var image = details[0]['Record']['image'];
//                 var contact = details[0]['Record']['contact'];
//                 var address = details[0]['Record']['address'];
//                 var description = details[0]['Record']['description'];
//                 var signupDate = details[0]['Record']['signupDate'];
//                 var signupStatus = details[0]['Record']['signupStatus'];
//                 var stripeAccountId=details[0]['Record']['stripeAccountId'];
//                 var chargesEnabled=details[0]['Record']['chargesEnabled'];
//                 var detailsSubmitted=details[0]['Record']['detailsSubmitted'];
//                 var subscribed=details[0]['Record']['subscribed'];
//                 var cusID=details[0]['Record']['customerID'];

//                 //now updating
//                 var updatedUser = await contract.submitTransaction("updateUser", userId, email, name, newPasswordLength, image, userType, contact, address, description, signupDate, signupStatus,stripeAccountId,chargesEnabled,detailsSubmitted,subscribed,cusID, newPasswordDate);

//                 await gateway.disconnect();

//                 logger.debug(chalk.bold("Updated User: "), JSON.parse(updatedUser.toString()));

//                 return "Done on " + newPasswordDate;
//             }
//             else
//             {
//                 return "Can't Update Admin Password";
//             }
//         }
//         return "UnRegistered";
//     }
//     catch(error)
//     {
//         logger.error(`Failed to perform query: ${error}`);
//         return error.message;
//     }

// }


const isUserRegistered = async (username, userOrg) => {
    const walletPath = await getWalletPath(userOrg)
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);

    const userIdentity = await wallet.get(username);
    if (userIdentity) {
        console.log(`An identity for the user ${username} exists in the wallet`);
        return true
    }
    return false
}


const getCaInfo = async (org, ccp) => {
    let caInfo
    if (org == "Org1") {
        caInfo = ccp.certificateAuthorities['ca.org1.example.com'];

    } else if (org == "Org2") {
        caInfo = ccp.certificateAuthorities['ca.org2.example.com'];
    } else
        return null
    return caInfo

}

const enrollAdmin = async (org, ccp) => {

    console.log('calling enroll Admin method')

    try {

        const caInfo = await getCaInfo(org, ccp) //ccp.certificateAuthorities['ca.org1.example.com'];
        const caTLSCACerts = caInfo.tlsCACerts.pem;
        const ca = new FabricCAServices(caInfo.url, { trustedRoots: caTLSCACerts, verify: false }, caInfo.caName);

        // Create a new file system based wallet for managing identities.
        const walletPath = await getWalletPath(org) //path.join(process.cwd(), 'wallet');
        const wallet = await Wallets.newFileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the admin user.
        const identity = await wallet.get('admin');
        if (identity) {
            console.log('An identity for the admin user "admin" already exists in the wallet');
            return;
        }

        // Enroll the admin user, and import the new identity into the wallet.
        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
        let x509Identity;
        if (org == "Org1") {
            x509Identity = {
                credentials: {
                    certificate: enrollment.certificate,
                    privateKey: enrollment.key.toBytes(),
                },
                mspId: 'Org1MSP',
                type: 'X.509',
            };
        } else if (org == "Org2") {
            x509Identity = {
                credentials: {
                    certificate: enrollment.certificate,
                    privateKey: enrollment.key.toBytes(),
                },
                mspId: 'Org2MSP',
                type: 'X.509',
            };
        }

        await wallet.put('admin', x509Identity);
        console.log('Successfully enrolled admin user "admin" and imported it into the wallet');
        return
    } catch (error) {
        console.error(`Failed to enroll admin user "admin": ${error}`);
    }
}

const registerAndGerSecret = async (username, userOrg) => {
    let ccp = await getCCP(userOrg)

    const caURL = await getCaUrl(userOrg, ccp)
    const ca = new FabricCAServices(caURL);

    const walletPath = await getWalletPath(userOrg)
    const wallet = await Wallets.newFileSystemWallet(walletPath);
    console.log(`Wallet path: ${walletPath}`);

    const userIdentity = await wallet.get(username);
    if (userIdentity) {
        console.log(`An identity for the user ${username} already exists in the wallet`);
        var response = {
            success: true,
            message: username + ' enrolled Successfully',
        };
        return response
    }

    // Check to see if we've already enrolled the admin user.
    let adminIdentity = await wallet.get('admin');
    if (!adminIdentity) {
        console.log('An identity for the admin user "admin" does not exist in the wallet');
        await enrollAdmin(userOrg, ccp);
        adminIdentity = await wallet.get('admin');
        console.log("Admin Enrolled Successfully")
    }

    // build a user object for authenticating with the CA
    const provider = wallet.getProviderRegistry().getProvider(adminIdentity.type);
    const adminUser = await provider.getUserContext(adminIdentity, 'admin');
    let secret;
    try {
        // Register the user, enroll the user, and import the new identity into the wallet.
        secret = await ca.register({ affiliation: await getAffiliation(userOrg), enrollmentID: username, role: 'client' }, adminUser);
        // const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: username, role: 'client', attrs: [{ name: 'role', value: 'approver', ecert: true }] }, adminUser);

    } catch (error) {
        return error.message
    }

    var response = {
        success: true,
        message: username + ' enrolled Successfully',
        secret: secret
    };
    return response

}

exports.getRegisteredUser = getRegisteredUser

module.exports = {
    getCCP: getCCP,
    getWalletPath: getWalletPath,
    getRegisteredUser: getRegisteredUser,
    isUserRegistered: isUserRegistered,
    registerAndGerSecret: registerAndGerSecret,
    updatePassword: updatePassword

}
