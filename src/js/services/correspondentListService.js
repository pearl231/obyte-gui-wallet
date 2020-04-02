'use strict';

var constants = require('ocore/constants.js');
var eventBus = require('ocore/event_bus.js');
var ValidationUtils = require('ocore/validation_utils.js');
var objectHash = require('ocore/object_hash.js');

angular.module('copayApp.services').factory('correspondentListService', function($state, $rootScope, $sce, $compile, configService, storageService, profileService, go, lodash, $stickyState, $deepStateRedirect, $timeout, gettext, isCordova, pushNotificationsService) {
	var root = {};
	var crypto = require('crypto');
	var device = require('ocore/device.js');
	var wallet = require('ocore/wallet.js');
	var chatStorage = require('ocore/chat_storage.js');

	$rootScope.newMessagesCount = {};
	$rootScope.newMsgCounterEnabled = false;
	$rootScope.newPaymentsCount = {};

	if (typeof nw !== 'undefined') {
		var messagesCount;
		var paymentsCount;
		var win = nw.Window.get();
		win.on('focus', function(){
			$rootScope.newMsgCounterEnabled = false;
		});
		win.on('blur', function(){
			$rootScope.newMsgCounterEnabled = true;
		});

		$rootScope.$watch('newMessagesCount', function(counters) {
			messagesCount = lodash.sum(lodash.values(counters));
			if (messagesCount || paymentsCount) {
				win.setBadgeLabel(""+ (messagesCount + paymentsCount));
			} else {
				win.setBadgeLabel("");
			}
		}, true);

		$rootScope.$watch('newPaymentsCount', function(counters) {
			paymentsCount = lodash.sum(lodash.values(counters));
			if (paymentsCount || messagesCount) {
				win.setBadgeLabel(""+ (messagesCount + paymentsCount));
			} else {
				win.setBadgeLabel("");
			}
		}, true);
	}

	$rootScope.$watch('newMessagesCount', function(counters) {
		$rootScope.totalNewMsgCnt = lodash.sum(lodash.values(counters));
	}, true);

	$rootScope.$watch('newPaymentsCount', function(counters) {
		$rootScope.totalNewPaymentsCnt = lodash.sum(lodash.values(counters));
	}, true);


	
	function addIncomingMessageEvent(from_address, in_body, message_counter){
		var walletGeneral = require('ocore/wallet_general.js');
		walletGeneral.readMyAddresses(function(arrMyAddresses){
			var body = highlightActions(in_body, arrMyAddresses);
			addMessageEvent(true, from_address, body, message_counter);
		});
	}
	
	function addMessageEvent(bIncoming, peer_address, body, message_counter, skip_history_load){
		if (!root.messageEventsByCorrespondent[peer_address] && !skip_history_load) {
			return loadMoreHistory({device_address: peer_address}, function() {
				addMessageEvent(bIncoming, peer_address, body, message_counter, true);
			});
		}
		//root.messageEventsByCorrespondent[peer_address].push({bIncoming: true, message: $sce.trustAsHtml(body)});
		if (bIncoming) {

			if (peer_address in $rootScope.newMessagesCount)
				$rootScope.newMessagesCount[peer_address]++;
			else {
				$rootScope.newMessagesCount[peer_address] = 1;
			}
			if ($rootScope.newMessagesCount[peer_address] == 1 && (!$state.is('correspondentDevices.correspondentDevice') || root.currentCorrespondent.device_address != peer_address)) {
				root.messageEventsByCorrespondent[peer_address].push({
					bIncoming: false,
					message: {
						type: 'newMessages'
					},
					type: 'system',
					new_message_delim: true
				});
			}
		}
		var msg_obj = {
			bIncoming: bIncoming,
			message: body,
			timestamp: Math.floor(Date.now() / 1000),
			message_counter: message_counter
		};
		checkAndInsertDate(root.messageEventsByCorrespondent[peer_address], msg_obj);
		insertMsg(root.messageEventsByCorrespondent[peer_address], msg_obj);
		root.assocLastMessageDateByCorrespondent[peer_address] = new Date().toISOString().substr(0, 19).replace('T', ' ');
		if ($state.is('walletHome') && $rootScope.tab == 'walletHome') {
			setCurrentCorrespondent(peer_address, function(bAnotherCorrespondent){
				$timeout(function(){
					$stickyState.reset('correspondentDevices.correspondentDevice');
					go.path('correspondentDevices.correspondentDevice');
				});
			});
		}
		else
			$timeout(function(){
				$rootScope.$digest();
			});
	}

	function insertMsg(messages, msg_obj) {
		for (var i = messages.length-1; i >= 0 && msg_obj.message_counter; i--) {
			var message = messages[i];
			if (message.message_counter === undefined || message.message_counter && msg_obj.message_counter > message.message_counter) {
				messages.splice(i+1, 0, msg_obj);
				return;
			}
		}
		messages.push(msg_obj);
	}
	
	
	// payment description within [] is ignored and whole URI is capturing group
	var payment_request_regexp = /\[.*?\]\(((?:byteball-tn|byteball|obyte-tn|obyte):([0-9A-Z]{32})(?:\?([\w=&;+%]+))?)\)/g;
	var pairing_regexp = /\[.*?\]\(((?:byteball-tn|byteball|obyte-tn|obyte):([\w\/+]{44})@([\w.:\/-]+)#(.+))\)/g;
	var textcoin_regexp = /\[.*?\]\(((?:byteball-tn|byteball|obyte-tn|obyte):textcoin\?([a-z-]+))\)/g;
	var data_regexp = /\[.*?\]\(((?:byteball-tn|byteball|obyte-tn|obyte):data\?(.+))\)/g;
	var url_regexp = /\bhttps?:\/\/[\w+&@#/%?=~|!:,.;-]+[\w+&@#/%=~|-]/g;


	function highlightActions(text, arrMyAddresses){
		var URI = require('ocore/uri.js');
	//	return text.replace(/\b[2-7A-Z]{32}\b(?!(\?(amount|asset|device_address|single_address)|"))/g, function(address){
		var assocReplacements = {};
		var token = crypto.randomBytes(4).readUInt32BE(0);
		var index = crypto.randomBytes(4).readUInt32BE(0);
		
		function tokenize(obj) {
			index++;
			assocReplacements[index] = obj;
			return token.toString() + index.toString() + token.toString();
		}

		var text = text.replace(/(.*?\s|^)([2-7A-Z]{32})([\s.,;!:].*?|$)/g, function(str, pre, address, post){
			if (!ValidationUtils.isValidAddress(address))
				return str;
			if (pre.lastIndexOf(')') < pre.lastIndexOf(']('))
				return str;
			if (post.indexOf('](') < post.indexOf('[') || (post.indexOf('](') > -1) && (post.indexOf('[') == -1))
				return str;
		//	if (arrMyAddresses.indexOf(address) >= 0)
		//		return address;
			//return '<a send-payment address="'+address+'">'+address+'</a>';
			return tokenize({
				type: 'paymentDropdown',
				address: address
			});
		//	return '<a ng-click="sendPayment(\''+address+'\')">'+address+'</a>';
			//return '<a send-payment ng-click="sendPayment(\''+address+'\')">'+address+'</a>';
			//return '<a send-payment ng-click="console.log(\''+address+'\')">'+address+'</a>';
			//return '<a onclick="console.log(\''+address+'\')">'+address+'</a>';
		}).replace(payment_request_regexp, function(str, uri, address, query_string){
			if (!ValidationUtils.isValidAddress(address))
				return str;
		//	if (arrMyAddresses.indexOf(address) >= 0)
		//		return str;
			var objPaymentRequest = parsePaymentRequestQueryString(query_string);
			if (!objPaymentRequest) {
				return tokenize({
					type: 'paymentDropdown',
					address: address
				});
			}
			return tokenize({
				type: 'paymentRequest',
				amount: objPaymentRequest.amount,
				asset: objPaymentRequest.asset,
				device_address: objPaymentRequest.device_address,
				single_address: objPaymentRequest.single_address,
				base64data: objPaymentRequest.base64data,
				amountStr: objPaymentRequest.amountStr
			});
		}).replace(pairing_regexp, function(str, uri, device_pubkey, hub, pairing_code){
			return tokenize({
				type: 'pairingCode', 
				device_pubkey: device_pubkey,
				hub: hub,
				pairing_code: pairing_code,
				uri: uri
			});
		}).replace(textcoin_regexp, function(str, uri, mnemonic){
			return tokenize({
				type: 'textcoin',
				uri: uri,
				mnemonic: mnemonic
			});
		}).replace(data_regexp, function(str, uri, query_string){
			var assocParams = query_string ? URI.parseQueryString(query_string, '&amp;') : null;
			if (!assocParams)
				return str;
			
			return tokenize({
				type: 'data',
				uri: uri,
				data: JSON.stringify(assocParams, null, 2)
			})
		}).replace(/\[(.+?)\]\(suggest-command:(.+?)\)/g, function(str, description, command){
			return tokenize({
				type: 'suggestCommand',
				command: command,
				description: description
			});
		}).replace(/\[(.+?)\]\(command:(.+?)\)/g, function(str, description, command){
			return tokenize({
				type: 'command',
				command: command,
				description: description
			});
		}).replace(/\[(.+?)\]\(payment:([\w\/+=]+?)\)/g, function(str, description, paymentJsonBase64){
			var arrMovements = getMovementsFromJsonBase64PaymentRequest(paymentJsonBase64, true);
			if (!arrMovements)
				return tokenize(invalidMessage('payment request'));

			description = 'Payment request: '+arrMovements.join(', ');
			return tokenize({
				type: 'sendPayment',
				paymentJsonBase64: paymentJsonBase64,
				description: description
			});
		}).replace(/\[(.+?)\]\(vote:([\w\/+=]+?)\)/g, function(str, description, voteJsonBase64){
			var objVote = getVoteFromJsonBase64(voteJsonBase64);
			if (!objVote)
				return tokenize(invalidMessage('vote request'));

			return tokenize({
				type: 'vote',
				voteJsonBase64: voteJsonBase64,
				choice: objVote.choice
			});
		}).replace(/\[(.+?)\]\(profile:([\w\/+=]+?)\)/g, function(str, description, privateProfileJsonBase64){
			var objPrivateProfile = getPrivateProfileFromJsonBase64(privateProfileJsonBase64);
			if (!objPrivateProfile)
				return tokenize(invalidMessage('profile'));

			return tokenize({
				type: 'profile',
				privateProfileJsonBase64: privateProfileJsonBase64,
				label: objPrivateProfile._label
			});
		}).replace(/\[(.+?)\]\(profile-request:([\w,]+?)\)/g, function(str, description, fields_list){
			return tokenize({
				type: 'profileRequest',
				fields_list: fields_list
			});
		}).replace(/\[(.+?)\]\(sign-message-request(-network-aware)?:(.+?)\)/g, function(str, description, network_aware, message_to_sign){
			return tokenize({
				type: 'signMessageRequest',
				message_to_sign: message_to_sign,
				network_aware: network_aware
			});
		}).replace(/\[(.+?)\]\(signed-message:([\w\/+=]+?)\)/g, function(str, description, signedMessageBase64){
			var info = getSignedMessageInfoFromJsonBase64(signedMessageBase64);
			if (!info)
				return tokenize(invalidMessage('signed message'));

			var objSignedMessage = info.objSignedMessage;
			var displayed_signed_message = (typeof objSignedMessage.signed_message === 'string') ? objSignedMessage.signed_message : JSON.stringify(objSignedMessage.signed_message, null, '\t');
			var text = 'Message signed by '+objSignedMessage.authors[0].address+': '+escapeHtml(displayed_signed_message);
			if (info.bValid)
				text += " (valid)";
			else if (info.bValid === false)
				text += " (invalid)";

			return tokenize({
				type: 'signedMessage',
				text: text,
				verify: typeof info.bValid === 'undefined',
				signedMessageBase64: signedMessageBase64
			});
		}).replace(url_regexp, function(str){
			return tokenize({
				type: 'openExternalLink',
				link: str
			});
		}).replace(/\(prosaic-contract:([\w\/+=]+?)\)/g, function(str, contractJsonBase64){
			var objContract = getProsaicContractFromJsonBase64(contractJsonBase64);
			if (!objContract)
				return tokenize(invalidMessage('contract'));
			
			return tokenize({
				type: 'prosaicContract',
				contractJsonBase64: contractJsonBase64,
				status: objContract.status ? escapeHtml(objContract.status) : 'offer',
				title: objContract.title
			})
		}).replace(/\n/g, function(str) {
			return tokenize({
				type: 'newline'
			});
		}).replace(/\t/g, function(str) {
			return tokenize({
				type: 'tab'
			});
		});

		var parts = [];
		var tokens = text.split(token);
		for (var idx in tokens) {
			var tokenized = tokens[idx];
			
			if( tokenized.length == 0 ) continue;

			if( tokenized in assocReplacements ) {
				parts.push(assocReplacements[tokenized]);
			} else {
				parts.push({
					type: 'text',
					text: tokenized
				});
			}
		}

		return parts;
	}
	
	function getMovementsFromJsonBase64PaymentRequest(paymentJsonBase64, bAggregatedByAsset){
		if (!ValidationUtils.isValidBase64(paymentJsonBase64))
			return null;
		var paymentJson = Buffer.from(paymentJsonBase64, 'base64').toString('utf8');
		console.log(paymentJson);
		try{
			var objMultiPaymentRequest = JSON.parse(paymentJson);
		}
		catch(e){
			return null;
		}
		if (!ValidationUtils.isNonemptyArray(objMultiPaymentRequest.payments))
			return null;
		if (!objMultiPaymentRequest.payments.every(function(objPayment){
			return ( ValidationUtils.isValidAddress(objPayment.address) && ValidationUtils.isPositiveInteger(objPayment.amount) && (!objPayment.asset || objPayment.asset === "base" || ValidationUtils.isValidBase64(objPayment.asset, constants.HASH_LENGTH)) );
		}))
			return null;
		if (objMultiPaymentRequest.definitions){
			for (var destinationAddress in objMultiPaymentRequest.definitions){
				var arrDefinition = objMultiPaymentRequest.definitions[destinationAddress].definition;
				try {
					if (destinationAddress !== objectHash.getChash160(arrDefinition))
						return null;
				}
				catch(e){
					console.log(e);
					return null;
				}
			}
		}
		try{
			var assocPaymentsByAsset = getPaymentsByAsset(objMultiPaymentRequest);
		}
		catch(e){
			return null;
		}
		var arrMovements = [];
		if (bAggregatedByAsset)
			for (var asset in assocPaymentsByAsset)
				arrMovements.push(getAmountText(assocPaymentsByAsset[asset], asset));
		else
			arrMovements = objMultiPaymentRequest.payments.map(function(objPayment){
				return getAmountText(objPayment.amount, objPayment.asset || 'base') + ' to ' + objPayment.address;
			});
		return arrMovements;
	}
	
	function getVoteFromJsonBase64(voteJsonBase64){
		if (!ValidationUtils.isValidBase64(voteJsonBase64))
			return null;
		var voteJson = Buffer.from(voteJsonBase64, 'base64').toString('utf8');
		console.log(voteJson);
		try{
			var objVote = JSON.parse(voteJson);
		}
		catch(e){
			return null;
		}
		if (!ValidationUtils.isStringOfLength(objVote.poll_unit, 44) || typeof objVote.choice !== 'string')
			return null;
		return objVote;
	}
	
	function getPrivateProfileFromJsonBase64(privateProfileJsonBase64){
		if (!ValidationUtils.isValidBase64(privateProfileJsonBase64))
			return null;
		var privateProfile = require('ocore/private_profile.js');
		var objPrivateProfile = privateProfile.getPrivateProfileFromJsonBase64(privateProfileJsonBase64);
		if (!objPrivateProfile)
			return null;
		var arrFirstFields = [];
		for (var field in objPrivateProfile.src_profile){
			var value = objPrivateProfile.src_profile[field];
			if (!Array.isArray(value))
				continue;
			arrFirstFields.push(value[0]);
			if (arrFirstFields.length === 2)
				break;
		}
		objPrivateProfile._label = arrFirstFields.join(' ');
		return objPrivateProfile;
	}

	function getProsaicContractFromJsonBase64(strJsonBase64){
		if (!ValidationUtils.isValidBase64(strJsonBase64))
			return null;
		var strJSON = Buffer.from(strJsonBase64, 'base64').toString('utf8');
		try{
			var objProsaicContract = JSON.parse(strJSON);
		}
		catch(e){
			return null;
		}
		if (!ValidationUtils.isValidAddress(objProsaicContract.my_address) || !objProsaicContract.text.length)
			return null;
		return objProsaicContract;
	}
	
	function getSignedMessageInfoFromJsonBase64(signedMessageBase64){
		if (!ValidationUtils.isValidBase64(signedMessageBase64))
			return null;
		var signedMessageJson = Buffer.from(signedMessageBase64, 'base64').toString('utf8');
		console.log(signedMessageJson);
		try{
			var objSignedMessage = JSON.parse(signedMessageJson);
		}
		catch(e){
			return null;
		}
		var info = {
			objSignedMessage: objSignedMessage,
			bValid: undefined
		};
		var validation = require('ocore/validation.js');
		validation.validateSignedMessage(objSignedMessage, function(err){
			info.bValid = !err;
			if (err)
				console.log("validateSignedMessage: "+err);
		});
		return info;
	}

	function tryParseBase64(str) {
		if (!ValidationUtils.isValidBase64(str))
			return str;
		var json = Buffer.from(str, 'base64').toString('utf8');
		try{
			var obj = JSON.parse(json);
		}
		catch(e){
			return str; // it is already escapeHtml'd
		}
		return escapeHtml(JSON.stringify(obj, null, '\t'));
	}
	
	function getPaymentsByAsset(objMultiPaymentRequest){
		var assocPaymentsByAsset = {};
		objMultiPaymentRequest.payments.forEach(function(objPayment){
			var asset = objPayment.asset || 'base';
			if (asset !== 'base' && !ValidationUtils.isValidBase64(asset, constants.HASH_LENGTH))
				throw Error("asset "+asset+" is not valid");
			if (!ValidationUtils.isPositiveInteger(objPayment.amount))
				throw Error("amount "+objPayment.amount+" is not valid");
			if (!assocPaymentsByAsset[asset])
				assocPaymentsByAsset[asset] = 0;
			assocPaymentsByAsset[asset] += objPayment.amount;
		});
		return assocPaymentsByAsset;
	}
	
	function invalidMessage(type) {
		return {
			type: 'invalid',
			invalid: type
		};
	}

	function formatOutgoingMessage(text){
		var URI = require('ocore/uri.js');
		var assocReplacements = {};
		var index = crypto.randomBytes(4).readUInt32BE(0);
		var token = crypto.randomBytes(4).readUInt32BE(0);

		// Function t short hand for tokenize
		function tokenize(obj) {
			index++;
			assocReplacements[index] = obj;
			return token.toString() + index.toString() + token.toString();
		}

		var text = text.replace(payment_request_regexp, function(str, uri, address, query_string){
			if (!ValidationUtils.isValidAddress(address))
				return str;
			var objPaymentRequest = parsePaymentRequestQueryString(query_string);
			return tokenize({
				type: 'sentPaymentRequest',
				amountStr: objPaymentRequest.amountStr,
				address: address
			});
		}).replace(/\[(.+?)\]\(payment:([\w\/+=]+?)\)/g, function(str, description, paymentJsonBase64){
			var arrMovements = getMovementsFromJsonBase64PaymentRequest(paymentJsonBase64);
			if (!arrMovements)
				return tokenize(invalidMessage('payment request'));

			return tokenize({
				type: 'paymentRequest',
				arrMovements: arrMovements
			});
		}).replace(pairing_regexp, function(str, uri, device_pubkey, hub, pairing_code){
			return tokenize({
				type: 'pairingCode',
				device_pubkey: device_pubkey,
				hub: hub,
				pairing_code: pairing_code
			});
		}).replace(textcoin_regexp, function(str, uri, mnemonic){
			return tokenize({
				type: 'textcoin',
				mnemonic: mnemonic
			});
		}).replace(data_regexp, function(str, uri, query_string){
			var assocParams = query_string ? URI.parseQueryString(query_string, '&amp;') : null;
			if (!assocParams)
				return str;

			return tokenize({
				type: 'data', 
				data: JSON.stringify(assocParams, null, 2)
			});
		}).replace(/\[(.+?)\]\(vote:([\w\/+=]+?)\)/g, function(str, description, voteJsonBase64){
			var objVote = getVoteFromJsonBase64(voteJsonBase64);
			if (!objVote)
				return tokenize(invalidMessage('vote request'));

			return tokenize({
				type: 'vote',
				choice: objVote.choice
			});
		}).replace(/\[(.+?)\]\(profile:([\w\/+=]+?)\)/g, function(str, description, privateProfileJsonBase64){
			var objPrivateProfile = getPrivateProfileFromJsonBase64(privateProfileJsonBase64);
			if (!objPrivateProfile)
				return tokenize(invalidMessage('profile'));

			return tokenize({
				type: 'profile',
				privateProfileJsonBase64: privateProfileJsonBase64,
				label: objPrivateProfile._label
			});
		}).replace(/\[(.+?)\]\(profile-request:([\w,]+?)\)/g, function(str, description, fields_list){
			return tokenize({
				type: 'profileRequest',
				fields_list: fields_list
			});
		}).replace(/\[(.+?)\]\(sign-message-request:(.+?)\)/g, function(str, description, message_to_sign){
			return tokenize({
				type: 'signMessageRequest',
				message_to_sign: message_to_sign
			});
		}).replace(/\[(.+?)\]\(signed-message:([\w\/+=]+?)\)/g, function(str, description, signedMessageBase64){
			var info = getSignedMessageInfoFromJsonBase64(signedMessageBase64);
			if (!info)
				return tokenize(invalidMessage('signed message'));

			var objSignedMessage = info.objSignedMessage;
			var displayed_signed_message = (typeof objSignedMessage.signed_message === 'string') ? objSignedMessage.signed_message : JSON.stringify(objSignedMessage.signed_message, null, '\t');
			var text = 'Message signed by '+objSignedMessage.authors[0].address+': '+escapeHtmlAndInsertBr(displayed_signed_message);
			if (info.bValid)
				text += " (valid)";
			else if (info.bValid === false)
				text += " (invalid)";

			return tokenize({
				type: 'signedMessage',
				signedMessageBase64: signedMessageBase64,
				text: text,
				verify: typeof info.bValid === 'undefined'
			});
		}).replace(url_regexp, function(str){
			return tokenize({
				type: 'openExternalLink',
				link: str
			});
		}).replace(/\(prosaic-contract:([\w\/+=]+?)\)/g, function(str, contractJsonBase64){
			var objContract = getProsaicContractFromJsonBase64(contractJsonBase64);
			if (!objContract)
				return tokenize(invalidMessage('contract'));

			return tokenize({
				type: 'prosaicContract',
				contractJsonBase64: contractJsonBase64,
				status: objContract.status ? objContract.status : 'offer',
				title: objContract.title
			});
		}).replace(/\n/g, function(str) {
			return tokenize({
				type: 'newline'
			});
		}).replace(/\t/g, function(str) {
			return tokenize({
				type: 'tab'
			});
		});

		var parts = [];
		var tokens = text.split(token);
		for (var idx in tokens) {
			var tokenized = tokens[idx];
			
			if( tokenized.length == 0 ) continue;

			if( tokenized in assocReplacements ) {
				parts.push(assocReplacements[tokenized]);
			} else {
				parts.push({
					type: 'text',
					text: tokenized
				});
			}
		}

		return parts;
	}
	
	function parsePaymentRequestQueryString(query_string){
		if (!query_string)
			return null;
		var URI = require('ocore/uri.js');
		var assocParams = URI.parseQueryString(query_string, '&amp;');
		var strAmount = assocParams['amount'];
		if (!strAmount)
			return null;
		var amount = parseInt(strAmount);
		if (amount + '' !== strAmount)
			return null;
		if (!ValidationUtils.isPositiveInteger(amount))
			return null;
		var asset = assocParams['asset'] || 'base';
		console.log("asset="+asset);
		if (asset !== 'base' && !ValidationUtils.isValidBase64(asset, constants.HASH_LENGTH)) // invalid asset
			return null;
		var device_address = assocParams['device_address'] || '';
		if (device_address && !ValidationUtils.isValidDeviceAddress(device_address))
			return null;
		var single_address = assocParams['single_address'] || 0;
		if (single_address)
			single_address = single_address.replace(/^single/, '');
		if (single_address && !ValidationUtils.isValidAddress(single_address))
			single_address = 1;
		var base64data = assocParams['base64data'] || '';
		if (base64data && !ValidationUtils.isValidBase64(base64data))
			return null;
		var amountStr = 'Payment request'+(base64data ? ' with data': '')+': ' + getAmountText(amount, asset);
		return {
			amount: amount,
			asset: asset,
			device_address: device_address,
			amountStr: amountStr,
			single_address: single_address,
			base64data: base64data
		};
	}
	
	function text2html(text){
		return text.toString().replace(/\r/g, '').replace(/\n/g, '<br>').replace(/\t/g, ' &nbsp; &nbsp; ');
	}
	
	function escapeHtml(text){
		return text.toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	}
	
	function escapeHtmlAndInsertBr(text){
		return text2html(escapeHtml(text));
	}
	
	function escapeQuotes(text){
		return text.toString().replace(/(['\\])/g, "\\$1").replace(/"/g, "&quot;");
	}
	
	function setCurrentCorrespondent(correspondent_device_address, onDone){
		if (!root.currentCorrespondent || correspondent_device_address !== root.currentCorrespondent.device_address)
			device.readCorrespondent(correspondent_device_address, function(correspondent){
				root.currentCorrespondent = correspondent;
				onDone(true);
			});
		else
			onDone(false);
	}
	
	// amount is in smallest units
	function getAmountText(amount, asset){
		if (asset === 'base'){
			var walletSettings = configService.getSync().wallet.settings;
			var unitValue = walletSettings.unitValue;
			var unitName = walletSettings.unitName;
			if (amount !== 'all')
				amount /= unitValue;
			return amount + ' ' + unitName;
		}
		else if (asset === constants.BLACKBYTES_ASSET){
			var walletSettings = configService.getSync().wallet.settings;
			var bbUnitValue = walletSettings.bbUnitValue;
			var bbUnitName = walletSettings.bbUnitName;
			amount /= bbUnitValue;
			return amount + ' ' + bbUnitName;
		}
		else if (profileService.assetMetadata[asset]){
			amount /= Math.pow(10, profileService.assetMetadata[asset].decimals || 0);
			return amount + ' ' + escapeHtml(profileService.assetMetadata[asset].name);
		}
		else{
			wallet.readAssetMetadata([asset], function(){});
			return amount + ' of ' + asset;
		}
	}
		
	function getHumanReadableDefinition(arrDefinition, arrMyAddresses, arrMyPubKeys, assocPeerNamesByAddress, bWithLinks){
		function getDisplayAddress(address){
			if (arrMyAddresses.indexOf(address) >= 0)
				return '<span title="your address: '+address+'">you</span>';
			if (assocPeerNamesByAddress[address])
				return '<span title="peer address: '+address+'">'+escapeHtml(assocPeerNamesByAddress[address])+'</span>';
			return address;
		}
		function parse(arrSubdefinition){
			var op = arrSubdefinition[0];
			var args = arrSubdefinition[1];
			switch(op){
				case 'sig':
					var pubkey = args.pubkey;
					return 'signed by '+(arrMyPubKeys.indexOf(pubkey) >=0 ? 'you' : 'public key '+escapeHtml(pubkey));
				case 'address':
					var address = args;
					return 'signed by '+getDisplayAddress(address);
				case 'cosigned by':
					var address = args;
					return 'co-signed by '+getDisplayAddress(address);
				case 'not':
					return '<span class="size-18">not</span>'+parseAndIndent(args);
				case 'or':
				case 'and':
					return args.map(parseAndIndent).join('<span class="size-18">'+op+'</span>');
				case 'r of set':
					return 'at least '+args.required+' of the following is true:<br>'+args.set.map(parseAndIndent).join(',');
				case 'weighted and':
					return 'the total weight of the true conditions below is at least '+args.required+':<br>'+args.set.map(function(arg){
						return arg.weight+': '+parseAndIndent(arg.value);
					}).join(',');
				case 'timestamp':
					var relation = args[0];
					var timestamp = args[1];
					var when = '';
					if (relation === '>' || relation === '>=')
						when = 'after';
					if (relation === '<' || relation === '<=')
						when = 'before';
					if (relation === '=')
						when = 'at';
					if (relation === '!=')
						when = 'not at';
					return when + ' ' + (new Date(timestamp * 1000).toString());
				case 'in data feed':
					var arrAddresses = args[0];
					var feed_name = args[1];
					var relation = args[2];
					var value = args[3];
					var min_mci = args[4];
					if (feed_name === 'timestamp' && relation === '>' && (typeof value === 'number' || parseInt(value).toString() === value))
						return 'after ' + ((typeof value === 'number') ? new Date(value).toString() : new Date(parseInt(value)).toString());
					var str = 'Oracle '+arrAddresses.join(', ')+' posted '+escapeHtml(feed_name)+' '+relation+' '+escapeHtml(value);
					if (min_mci)
						str += ' after MCI '+min_mci;
					return str;
				case 'in merkle':
					var arrAddresses = args[0];
					var feed_name = args[1];
					var value = args[2];
					var min_mci = args[3];
					var str = 'A proof is provided that oracle '+arrAddresses.join(', ')+' posted '+escapeHtml(value)+' in '+escapeHtml(feed_name);
					if (min_mci)
						str += ' after MCI '+min_mci;
					return str;
				case 'has':
					if (args.what === 'output' && args.asset && args.amount_at_least && args.address)
						return 'sends at least ' + getAmountText(args.amount_at_least, args.asset) + ' to ' + getDisplayAddress(args.address);
					if (args.what === 'output' && args.asset && args.amount && args.address)
						return 'sends ' + getAmountText(args.amount, args.asset) + ' to ' + getDisplayAddress(args.address);
					return escapeHtml(JSON.stringify(arrSubdefinition));
				case 'seen':
					if (args.what === 'output' && args.asset && args.amount && args.address){
						var dest_address = ((args.address === 'this address') ? objectHash.getChash160(arrDefinition) : args.address);
						var bOwnAddress = (arrMyAddresses.indexOf(args.address) >= 0);
						var expected_payment = getAmountText(args.amount, args.asset) + ' to ' + getDisplayAddress(args.address);
						return 'there was a transaction that sends ' + ((bWithLinks && !bOwnAddress) ? ('<a ng-click="sendPayment(\''+dest_address+'\', '+args.amount+', \''+args.asset+'\')">'+expected_payment+'</a>') : expected_payment);
					}
					else if (args.what === 'input' && (args.asset && args.amount || !args.asset && !args.amount) && args.address){
						var how_much = (args.asset && args.amount) ? getAmountText(args.amount, args.asset) : '';
						return 'there was a transaction that spends '+how_much+' from '+args.address;
					}
					return escapeHtml(JSON.stringify(arrSubdefinition));

				default:
					return escapeHtml(JSON.stringify(arrSubdefinition));
			}
		}
		function parseAndIndent(arrSubdefinition){
			return '<div class="indent">'+parse(arrSubdefinition)+'</div>\n';
		}
		return parse(arrDefinition, 0);
	}

	var historyEndForCorrespondent = {};
	function loadMoreHistory(correspondent, cb) {
		if (historyEndForCorrespondent[correspondent.device_address]) {
			if (cb) cb();
			return;
		}
		if (!root.messageEventsByCorrespondent[correspondent.device_address])
			root.messageEventsByCorrespondent[correspondent.device_address] = [];
		var messageEvents = root.messageEventsByCorrespondent[correspondent.device_address];
		var limit = 40;
		var last_msg_ts = null;
		var last_msg_id = 90071992547411;
		if (messageEvents.length && messageEvents[0].id) {
			last_msg_ts = new Date(messageEvents[0].timestamp * 1000);
			last_msg_id = messageEvents[0].id;
		}
		chatStorage.load(correspondent.device_address, last_msg_id, limit, function(messages){
			for (var i in messages) {
				messages[i] = parseMessage(messages[i]);
			}
			var walletGeneral = require('ocore/wallet_general.js');
			walletGeneral.readMyAddresses(function(arrMyAddresses){
				if (messages.length < limit)
					historyEndForCorrespondent[correspondent.device_address] = true;
				for (var i in messages) {
					var message = messages[i];
					var msg_ts = new Date(message.creation_date.replace(' ', 'T')+'.000Z');
					if (last_msg_ts && last_msg_ts.getDay() != msg_ts.getDay()) {
						messageEvents.unshift({
							type: 'system', 
							bIncoming: false, 
							message: {
								type: 'timestamp',
								date: last_msg_ts.toDateString()
							}, 
							timestamp: Math.floor(msg_ts.getTime() / 1000)
						});	
					}
					last_msg_ts = msg_ts;
					if (message.type == "text") {
						if (message.is_incoming) {
							message.message = highlightActions(message.message, arrMyAddresses);
							// message.message.text = text2html(message.message.text);
						} else {
							message.message = formatOutgoingMessage(message.message);
						}
					}
					messageEvents.unshift({id: message.id, type: message.type, bIncoming: message.is_incoming, message: message.message, timestamp: Math.floor(msg_ts.getTime() / 1000), chat_recording_status: message.chat_recording_status});
				}
				if (historyEndForCorrespondent[correspondent.device_address] && messageEvents.length > 1) {
					messageEvents.unshift({
						type: 'system', 
						bIncoming: false, 
						message: {
							type: 'timestamp',
							date: (last_msg_ts ? last_msg_ts : new Date()).toDateString()
						},
						timestamp: Math.floor((last_msg_ts ? last_msg_ts : new Date()).getTime() / 1000)
					});
				}
				if (cb) cb();
			});
		});
	}

	function checkAndInsertDate(messageEvents, message) {
		if (messageEvents.length == 0 || typeof messageEvents[messageEvents.length-1].timestamp == "undefined") return;

		var msg_ts = new Date(message.timestamp * 1000);
		var last_msg_ts = new Date(messageEvents[messageEvents.length-1].timestamp * 1000);
		if (last_msg_ts.getDay() != msg_ts.getDay()) {
			messageEvents.push({
				type: 'system', 
				bIncoming: false, 
				message: {
					type: 'timestamp',
					date: msg_ts.toDateString()
				 },
				 timestamp: Math.floor(msg_ts.getTime() / 1000)
			});	
		}
	}

	function parseMessage(message) {
		switch (message.type) {
			case "system":
				message.message = JSON.parse(message.message);
				message.message = {
					type: 'recordingPref',
					state: message.message.state
				};
				message.chat_recording_status = true;
				break;
			case "html": 
				/*
				Compatability layer for current and old messages
				stored as HTML.
				
				These were found by running the following and looking for html types:
				git rev-list --all | xargs -I% git --no-pager grep -F -e "chatStorage.store" % -- src/js/controllers/correspondentDevice.js
				git rev-list --all | xargs -I% git --no-pager grep -F -e "chatStorage.store" % -- src/js/services/correspondentListService.js
				
				**/

				// Currently in use for sent_payment and received_payment event handlers. TODO: Better storage of those types
				var match = message.message.match(/<a ng-click="showPayment\('([^']+)'\)" class="payment">(.+?): (.+?)<\/a>/);
				if (match.length) {
					message.message = {
						type: 'showPayment',
						asset: match[1],
						title: match[2],
						text: match[3]
					};
					break;
				}

				/* 4f612f74af78f7b41b1dc140f770b3f6abef4c5b:src/js/controllers/correspondentDevice.js

				paymentRequestCode = 'byteball:'+my_address+'?amount='+peer_amount+'&asset='+encodeURIComponent(contract.peerAsset);
				var paymentRequestText = '[your share of payment to the contract]('+paymentRequestCode+')';
				device.sendMessageToDevice(correspondent.device_address, 'text', paymentRequestText);
				var body = correspondentListService.formatOutgoingMessage(paymentRequestText);
				correspondentListService.addMessageEvent(false, correspondent.device_address, body);
				if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(correspondent.device_address, body, 0, 'html');
				*/
				match = message.message.match(/<i>(.+?) to (.+?)<\/i>/);
				if (match.length) {
					message.message = {
						type: 'sentPaymentRequest',
						amountStr: match[1],
						address: match[2]
					};
					break;
				}

				/* 4f612f74af78f7b41b1dc140f770b3f6abef4c5b:src/js/controllers/correspondentDevice.js

				var chat_message = "(prosaic-contract:" + Buffer.from(JSON.stringify(objContract), 'utf8').toString('base64') + ")";
				var body = correspondentListService.formatOutgoingMessage(chat_message);
				correspondentListService.addMessageEvent(false, correspondent.device_address, body);
				device.readCorrespondent(correspondent.device_address, function(correspondent) {
				if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(correspondent.device_address, body, 0, 'html');

				... 

				var chat_message = "(prosaic-contract:" + Buffer.from(JSON.stringify(objContract), 'utf8').toString('base64') + ")";
				var body = correspondentListService.formatOutgoingMessage(chat_message);
				correspondentListService.addMessageEvent(false, correspondent.device_address, body);
				if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(correspondent.device_address, body, 0, 'html');

				... 

				var chat_message = "(prosaic-contract:" + Buffer.from(JSON.stringify(objContract), 'utf8').toString('base64') + ")";
				var body = correspondentListService.formatOutgoingMessage(chat_message);
				correspondentListService.addMessageEvent(false, correspondent.device_address, body);
				if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(correspondent.device_address, body, 0, 'html');
				*/
				match = message.message.match(/\(prosaic-contract:([\w\/+=]+?)\)/);
				if (match.length) {
					objContract = getProsaicContractFromJsonBase64(match[1]);
					if (!objContract)
						break;
					
					message.message = {
						type: 'prosaicContract',
						contractJsonBase64: match[1],
						status: objContract.status ? objContract.status : 'offer',
						title: objContract.title
					};
					break;
				}



		}
		return message;
	}

	var message_signing_key_in_progress;
	function signMessageFromAddress(message, address, signingDeviceAddresses, bNetworkAware, cb) {
		var fc = profileService.focusedClient;
		if (fc.isPrivKeyEncrypted()) {
			profileService.unlockFC(null, function(err) {
				if (err){
					return cb(err.message);
				}
				signMessageFromAddress(message, address, signingDeviceAddresses, bNetworkAware, cb);
			});
			return;
		}
		
		profileService.requestTouchid(function(err) {
			if (err) {
				profileService.lockFC();
				return cb(err);
			}
			
			var current_message_signing_key = crypto.createHash("sha256").update(address + message).digest('base64');
			if (current_message_signing_key === message_signing_key_in_progress){
				return cb("This message signing is already under way");
			}
			message_signing_key_in_progress = current_message_signing_key;
			fc.signMessage(address, message, signingDeviceAddresses, bNetworkAware, function(err, objSignedMessage){
				message_signing_key_in_progress = null;
				if (err){
					return cb(err);
				}
				var signedMessageBase64 = Buffer.from(JSON.stringify(objSignedMessage)).toString('base64');
				cb(null, signedMessageBase64);
			});
		});
	}

	function populateScopeWithAttestedFields(scope, my_address, peer_address, cb) {
		var privateProfile = require('ocore/private_profile.js');
		scope.my_name = "NAME UNKNOWN";
		scope.my_attestor = {};
		scope.peer_name = "NAME UNKNOWN";
		scope.peer_attestor = {};
		async.series([function(cb2) {
			privateProfile.getFieldsForAddress(peer_address, ["first_name", "last_name"], lodash.map(configService.getSync().realNameAttestorAddresses, function(a){return a.address}), function(profile) {
				if (profile.first_name && profile.last_name) {
					scope.peer_name = profile.first_name +' '+ profile.last_name;
					scope.peer_attestor = {address: profile.attestor_address, attestation_unit: profile.attestation_unit, trusted: !!lodash.find(configService.getSync().realNameAttestorAddresses, function(attestor){return attestor.address == profile.attestor_address})}
				}
				cb2();
			});
		}, function(cb2) {
			privateProfile.getFieldsForAddress(my_address, ["first_name", "last_name"], lodash.map(configService.getSync().realNameAttestorAddresses, function(a){return a.address}), function(profile) {
				if (profile.first_name && profile.last_name) {
					scope.my_name = profile.first_name +' '+ profile.last_name;
					scope.my_attestor = {address: profile.attestor_address, attestation_unit: profile.attestation_unit, trusted: !!lodash.find(configService.getSync().realNameAttestorAddresses, function(attestor){return attestor.address == profile.attestor_address})}
				}
				cb2();
			});
		}, function(cb2) {
			if (Object.keys(scope.peer_attestor).length) return cb2();
			privateProfile.getFieldsForAddress(peer_address, ["name"], lodash.map(configService.getSync().realNameAttestorAddresses, function(a){return a.address}), function(profile) {
				if (profile.name) {
					scope.peer_name = profile.name;
					scope.peer_attestor = {address: profile.attestor_address, attestation_unit: profile.attestation_unit, trusted: !!lodash.find(configService.getSync().realNameAttestorAddresses, function(attestor){return attestor.address == profile.attestor_address})}
				}
				cb2();
			});
		}, function(cb2) {
			if (Object.keys(scope.my_attestor).length) return cb2();
			privateProfile.getFieldsForAddress(my_address, ["name"], lodash.map(configService.getSync().realNameAttestorAddresses, function(a){return a.address}), function(profile) {
				if (profile.name) {
					scope.my_name = profile.name;
					scope.my_attestor = {address: profile.attestor_address, attestation_unit: profile.attestation_unit, trusted: !!lodash.find(configService.getSync().realNameAttestorAddresses, function(attestor){return attestor.address == profile.attestor_address})}
				}
				cb2();
			});
		}], function(){
			cb();
		});
	}

	function openInExplorer(unit) {
		var testnet = constants.version.match(/t$/) ? 'testnet' : '';
		var url = 'https://' + testnet + 'explorer.obyte.org/#' + unit;
		if (typeof nw !== 'undefined')
			nw.Shell.openExternal(url);
		else if (isCordova)
			cordova.InAppBrowser.open(url, '_system');
	};

	/*eventBus.on("sign_message_from_address", function(message, address, signingDeviceAddresses) {
		signMessageFromAddress(message, address, signingDeviceAddresses, function(err, signedMessageBase64){
			if (signedMessageBase64)
				eventBus.emit("message_signed_from_address", message, address, signedMessageBase64);
		});
	});*/
	
	eventBus.on("text", function(from_address, body, message_counter){
		device.readCorrespondent(from_address, function(correspondent){
			if (!root.messageEventsByCorrespondent[correspondent.device_address]) loadMoreHistory(correspondent);
			addIncomingMessageEvent(correspondent.device_address, body, message_counter);
			if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(from_address, body, 1);
		});
	});

	eventBus.on("chat_recording_pref", function(correspondent_address, enabled, message_counter){
		device.readCorrespondent(correspondent_address, function(correspondent){
			var oldState = (correspondent.peer_record_pref && correspondent.my_record_pref);
			correspondent.peer_record_pref = enabled;
			var newState = (correspondent.peer_record_pref && correspondent.my_record_pref);
			device.updateCorrespondentProps(correspondent);
			if (newState != oldState) {
				if (!root.messageEventsByCorrespondent[correspondent_address]) root.messageEventsByCorrespondent[correspondent_address] = [];
				var message = {
					type: 'system',
					message: JSON.stringify({state: newState}),
					timestamp: Math.floor(Date.now() / 1000),
					chat_recording_status: true,
					message_counter: message_counter
				};
				insertMsg(root.messageEventsByCorrespondent[correspondent_address], parseMessage(message));
				$timeout(function(){
					$rootScope.$digest();
				});
				chatStorage.store(correspondent_address, JSON.stringify({state: newState}), 0, 'system');
			}
			if (root.currentCorrespondent && root.currentCorrespondent.device_address == correspondent_address) {
				root.currentCorrespondent.peer_record_pref = enabled ? 1 : 0;
			}
		});
	});

	eventBus.on("sent_payment", function(peer_address, amount, asset, bToSharedAddress){
		var title = bToSharedAddress ? 'Payment to smart address' : 'Payment';
		setCurrentCorrespondent(peer_address, function(bAnotherCorrespondent){
			var body = {
				type: 'showPayment',
				asset: asset,
				title: title,
				text: getAmountText(amount, asset)
			};
			addMessageEvent(false, peer_address, body);
			device.readCorrespondent(peer_address, function(correspondent){
				if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(peer_address, body, 0, 'html');
			});
			$timeout(function(){
				go.path('correspondentDevices.correspondentDevice');
			});
		});
	});

	eventBus.on("received_payment", function(peer_address, amount, asset, message_counter, bToSharedAddress){
		var title = bToSharedAddress ? 'Payment to smart address' : 'Payment';
		var body = {
			type: 'showPayment',
			asset: asset,
			title: title,
			text: getAmountText(amount, asset)
		};
		addMessageEvent(true, peer_address, body, message_counter);
		device.readCorrespondent(peer_address, function(correspondent){
			if (correspondent.my_record_pref && correspondent.peer_record_pref) chatStorage.store(peer_address, body, 1, 'html');
		});
	});

	eventBus.on('new_my_transactions', (arrNewUnits) => {
		arrNewUnits.forEach((unit) => {
			if (!$rootScope.newPaymentsCount[unit])
				$rootScope.newPaymentsCount[unit] = 1;
			else
				$rootScope.newPaymentsCount[unit]++;
		});
		delete $rootScope.newPaymentsCount[$rootScope.sentUnit];
	});
	
	eventBus.on('paired', function(device_address){
		pushNotificationsService.pushNotificationsInit();
		if ($state.is('correspondentDevices'))
			return $state.reload(); // refresh the list
		if (!$state.is('correspondentDevices.correspondentDevice'))
			return;
		if (!root.currentCorrespondent)
			return;
		if (device_address !== root.currentCorrespondent.device_address)
			return;
		// re-read the correspondent to possibly update its name
		device.readCorrespondent(device_address, function(correspondent){
			// do not assign a new object, just update its property (this object was already bound to a model)
			root.currentCorrespondent.name = correspondent.name;
			$timeout(function(){
				$rootScope.$digest();
			});
		});
	});

	 eventBus.on('removed_paired_device', function(device_address){
		if ($state.is('correspondentDevices'))
			return $state.reload(); // todo show popup after refreshing the list
		if (!$state.is('correspondentDevices.correspondentDevice'))
		 	return;
		if (!root.currentCorrespondent)
		 	return;
		if (device_address !== root.currentCorrespondent.device_address)
		 	return;
		
		// go back to list of correspondentDevices
		// todo show popup message
		// todo return to correspondentDevices when in edit-mode, too
		$deepStateRedirect.reset('correspondentDevices');
		go.path('correspondentDevices');
		$timeout(function(){
			$rootScope.$digest();
		});
	});
	

	$rootScope.$on('Local/CorrespondentInvitation', function(event, device_pubkey, device_hub, pairing_secret){
		console.log('CorrespondentInvitation', device_pubkey, device_hub, pairing_secret);
		root.acceptInvitation(device_hub, device_pubkey, pairing_secret, function(){});
	});

	
	root.getPaymentsByAsset = getPaymentsByAsset;
	root.getAmountText = getAmountText;
	root.setCurrentCorrespondent = setCurrentCorrespondent;
	root.formatOutgoingMessage = formatOutgoingMessage;
	root.getHumanReadableDefinition = getHumanReadableDefinition;
	root.loadMoreHistory = loadMoreHistory;
	root.checkAndInsertDate = checkAndInsertDate;
	root.parseMessage = parseMessage;
	root.escapeHtmlAndInsertBr = escapeHtmlAndInsertBr;
	root.addMessageEvent = addMessageEvent;
	root.getProsaicContractFromJsonBase64 = getProsaicContractFromJsonBase64;
	root.signMessageFromAddress = signMessageFromAddress;
	root.populateScopeWithAttestedFields = populateScopeWithAttestedFields;
	root.openInExplorer = openInExplorer;
	
	root.list = function(cb) {
	  device.readCorrespondents(function(arrCorrespondents){
		  cb(null, arrCorrespondents);
	  });
	};


	root.startWaitingForPairing = function(cb){
		device.startWaitingForPairing(function(pairingInfo){
			cb(pairingInfo);
		});
	};
	
	root.acceptInvitation = function(hub_host, device_pubkey, pairing_secret, cb){
		//return setTimeout(cb, 5000);
		if (device_pubkey === device.getMyDevicePubKey())
			return cb("cannot pair with myself");
		if (!device.isValidPubKey(device_pubkey))
			return cb("invalid peer public key");
		// the correspondent will be initially called 'New', we'll rename it as soon as we receive the reverse pairing secret back
		device.addUnconfirmedCorrespondent(device_pubkey, hub_host, 'New', function(device_address){
			device.startWaitingForPairing(function(reversePairingInfo){
				device.sendPairingMessage(hub_host, device_pubkey, pairing_secret, reversePairingInfo.pairing_secret, {
					ifOk: cb,
					ifError: cb
				});
			});
			// this continues in parallel
			// open chat window with the newly added correspondent
			device.readCorrespondent(device_address, function(correspondent){
				root.currentCorrespondent = correspondent;
				if (!$state.is('correspondentDevices.correspondentDevice'))
					go.path('correspondentDevices.correspondentDevice');
				else {
					$stickyState.reset('correspondentDevices.correspondentDevice');
					$state.reload();
				}
			});
		});
	};
	
	root.currentCorrespondent = null;
	root.messageEventsByCorrespondent = {};
	root.assocLastMessageDateByCorrespondent = {};

	root.listenForProsaicContractResponse = function(contracts) {
		var prosaic_contract = require('ocore/prosaic_contract.js');
		var storage = require('ocore/storage.js');
		var fc = profileService.focusedClient;

		var showError = function(msg) {
			$rootScope.$emit('Local/ShowErrorAlert', msg);
		}

		var start_listening = function(contracts) {
			contracts.forEach(function(contract){
				console.log('listening for prosaic contract response ' + contract.hash);

				var sendUnit = function(accepted, authors){
					if (!accepted) {
						return;
					}

					if (fc.isPrivKeyEncrypted()) {
						profileService.unlockFC(null, function(err) {
							if (err){
								showError(err);
								return;
							}
							sendUnit(accepted, authors);
						});
						return;
					}
					
					root.readLastMainChainIndex(function(err, last_mci){
						if (err){
							showError(err);
							return;
						}
						var arrDefinition = 
							['and', [
								['address', contract.my_address],
								['address', contract.peer_address]
							]];
						var assocSignersByPath = {
							'r.0': {
								address: contract.my_address,
								member_signing_path: 'r',
								device_address: device.getMyDeviceAddress()
							},
							'r.1': {
								address: contract.peer_address,
								member_signing_path: 'r',
								device_address: contract.peer_device_address
							}
						};
						require('ocore/wallet_defined_by_addresses.js').createNewSharedAddress(arrDefinition, assocSignersByPath, {
							ifError: function(err){
								showError(err);
							},
							ifOk: function(shared_address){
								composeAndSend(shared_address);
							}
						});
					});
					
					// create shared address and deposit some bytes to cover fees
					function composeAndSend(shared_address){
						prosaic_contract.setField(contract.hash, "shared_address", shared_address);
						device.sendMessageToDevice(contract.peer_device_address, "prosaic_contract_update", {
							hash: contract.hash,
							field: "shared_address",
							value: shared_address
						});
						contract.cosigners.forEach(function(cosigner){
							if (cosigner != device.getMyDeviceAddress())
								prosaic_contract.share(contract.hash, cosigner);
						});

						profileService.bKeepUnlocked = true;
						var opts = {
							asset: "base",
							to_address: shared_address,
							amount: prosaic_contract.CHARGE_AMOUNT,
							arrSigningDeviceAddresses: contract.cosigners
						};
						fc.sendMultiPayment(opts, function(err, unit){
							// if multisig, it might take very long before the callback is called
							//self.setOngoingProcess();
							profileService.bKeepUnlocked = false;
							$rootScope.sentUnit = unit;
							if (err){
								if (err.match(/device address/))
									err = "This is a private asset, please send it only by clicking links from chat";
								if (err.match(/no funded/))
									err = "Not enough spendable funds, make sure all your funds are confirmed";
								showError(err);
								return;
							}
							$rootScope.$emit("NewOutgoingTx");

							// post a unit with contract text hash and send it for signing to correspondent
							var value = {"contract_text_hash": contract.hash};
							var objMessage = {
								app: "data",
								payload_location: "inline",
								payload_hash: objectHash.getBase64Hash(value, storage.getMinRetrievableMci() >= constants.timestampUpgradeMci),
								payload: value
							};

							fc.sendMultiPayment({
								arrSigningDeviceAddresses: contract.cosigners.length ? contract.cosigners.concat([contract.peer_device_address]) : [],
								shared_address: shared_address,
								messages: [objMessage]
							}, function(err, unit) { // can take long if multisig
								//indexScope.setOngoingProcess(gettext('proposing a contract'), false);
								$rootScope.sentUnit = unit;
								if (err) {
									showError(err);
									return;
								}
								prosaic_contract.setField(contract.hash, "unit", unit);
								device.sendMessageToDevice(contract.peer_device_address, "prosaic_contract_update", {
									hash: contract.hash,
									field: "unit",
									value: unit
								});
								var testnet = constants.version.match(/t$/) ? 'testnet' : '';
								var url = 'https://' + testnet + 'explorer.obyte.org/#' + unit;
								var text = "unit with contract hash for \""+ contract.title +"\" was posted into DAG " + url;
								addMessageEvent(false, contract.peer_device_address, formatOutgoingMessage(text));
								device.sendMessageToDevice(contract.peer_device_address, "text", text);
							});
						});
					}
				};
				eventBus.once("prosaic_contract_response_received" + contract.hash, sendUnit);
			});
		}

		if (contracts)
			return start_listening(contracts);
		prosaic_contract.getAllByStatus("pending", function(contracts){
			start_listening(contracts);
		});
	}
	root.listenForProsaicContractResponse();

	root.readLastMainChainIndex = function(cb){
		if (require('ocore/conf.js').bLight){
			require('ocore/network.js').requestFromLightVendor('get_last_mci', null, function(ws, request, response){
				response.error ? cb(response.error) : cb(null, response);
			});
		}
		else
			require('ocore/storage.js').readLastMainChainIndex(function(last_mci){
				cb(null, last_mci);
			})
	}
  /*
  root.remove = function(addr, cb) {
	var fc = profileService.focusedClient;
	root.list(function(err, ab) {
	  if (err) return cb(err);
	  if (!ab) return;
	  if (!ab[addr]) return cb('Entry does not exist');
	  delete ab[addr];
	  storageService.setCorrespondentList(fc.credentials.network, JSON.stringify(ab), function(err) {
		if (err) return cb('Error deleting entry');
		root.list(function(err, ab) {
		  return cb(err, ab);
		});
	  });
	}); 
  };

  root.removeAll = function() {
	var fc = profileService.focusedClient;
	storageService.removeCorrespondentList(fc.credentials.network, function(err) {
	  if (err) return cb('Error deleting correspondentList');
	  return cb();
	});
  };*/

	return root;
});
