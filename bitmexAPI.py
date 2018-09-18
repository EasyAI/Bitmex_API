#! /usr/bin/env python3

"""
This is the bitmex REST API python call.
Official documentation can be found at 'https://www.bitmex.com/api/explorer/'
"""
import hmac
import hashlib
import requests
import time
import sys
from urllib.parse import urlencode


REAL_BASE = 'https://www.bitmex.com/api/v1'
TEST_BASE = 'https://testnet.bitmex.com/api/v1'


class Bitmex(object):

	def __init__(self, api_key=None, api_secret=None, testing=False):
		self.api_key = str(api_key) if api_key is not None else ''
		self.api_secret = str(api_secret) if api_secret is not None else ''
		self.BASE_URL = REAL_BASE if not(testing) else TEST_BASE


	## Announcements.
	def get_announcement(self, **OPargs):
		"""
		This is used to get announcements from bitmex.
		columns - string
		"""
		params = {}
		params.update(OPargs)
		data = self.api_request("GET", "/announcement", params)
		return(data)


	def get_urgent_announcement(self):
		"""
		This is used to get urgent announcements from bitmex.
		"""
		data = self.api_request("GET", "/announcement/urgent", {})
		return(data)


	## API Keys.
	def get_API_keys(self, **OPargs):
		"""
		This gets your API keys.

		PARAMS
		reverse - boolean
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/apiKey", params)
		return(data)


	def create_API_key(self, **OPargs):
		"""
		This creates an API key.

		PARAMS
		name - string
		cidr - string
		permissions - string
		enabled - boolean
		token - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/apiKey", params)
		return(data)


	def remove_API_key(self, apiKeyID):
		"""
		This deletes an API key.

		PARAMS
		apiKeyID - string
		"""
		params={"apiKeyID":apiKeyID}
		data = self.api_signed_request("DELETE", "/apiKey", params)
		return(data)


	def disable_API_key(self, apiKeyID):
		"""
		This disables your API key.

		PARAMS
		apiKeyID - string
		"""
		params={"apiKeyID":apiKeyID}
		data = self.api_signed_request("POST", "/apiKey/disable", params)
		return(data)


	def enable_API_key(self, apiKeyID):
		"""
		This enables your API key.

		PARAMS:
		apiKeyID - string
		"""
		params={"apiKeyID":apiKeyID}
		data = self.api_signed_request("POST", "/apiKey/enable", params)
		return(data)


	## Chat.
	def get_messages(self, **OPargs):
		"""
		This is used to get messages.
		
		PARAMS:
		count - double
		start - double
		reverse - boolean
		channelID - double
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/chat", params)
		return(data)


	def send_message(self, **OPargs):
		"""
		This is used to send messages.
		
		PARAMS:
		message - string
		channelID - double
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/chat", params)
		return(data)


	def available_channels(self):
		"""
		This is used to get channels.
		"""
		data = self.api_request("GET", "/chat/channels", {})
		return(data)


	def connected_users(self):
		"""
		This gets a list of connected users
		"""
		data = self.api_request("GET", "/chat/connected", {})
		return(data)


	## ComminicationToken. ## TO-DO


	## Execution.
	def get_executions(self, **OPargs):
		"""
		PARAMS:
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/execution", params)
		return(data)


	def get_all_executions(self, **OPargs):
		"""
		PARAMS:
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/execution/tradeHistory", params)
		return(data)


	## Funding.
	def funding_history(self, **OPargs):
		"""
		PARAMS:
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/funding", params)
		return(data)


	## Global Notification.
	def get_global_notifications(self):
		"""
		"""
		data = self.api_request("GET", "/globalNotification", {})
		return(data)


	## Instrument.
	def get_instruments(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/instrument", params)
		return(data)


	def get_all_instruments(self):
		"""
		"""
		data = self.api_request("GET", "/instrument/active", {})
		return(data)


	def active_indices(self):
		"""
		"""
		data = self.api_request("GET", "/instrument/activeAndIndices", {})
		return(data)


	def active_itervals(self):
		"""
		"""
		data = self.api_request("GET", "/activeIntervals", {})
		return(data)


	def composite_index(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/compositeIndex", params)
		return(data)


	def indice_prices(self):
		"""
		"""
		data = self.api_request("GET", "/indices", {})
		return(data)



	## Insurance.
	def get_insurance(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/insurance", params)
		return(data)



	## Leaderboard.
	def get_leaderboard(self, **OPargs):
		"""
		method - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/leaderboard", params)
		return(data)


	def get_leaderboard_name(self):
		"""
		"""
		data = self.api_signed_request("GET", "/leaderboard/name", {})
		return(data)



	## Liquidation.
	def get_liquidations(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/liquidation", params)
		return(data)



	## Notification. ## TO-DO
	def get_notifications(self):
		data = self.api_request("GET", "/notification")
		return(data)


	## Order.
	def get_orders(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/order", params)
		return(data)


	def amend_order(self, **OPargs):
		"""
		orderID - string
		origClOrdID - string
		clOrdID - string
		simpleOrderQty - double
		orderQty - double
		simpleLeavesQty - double
		leavesQty - double
		price - double
		stopPx - double
		pregOffsetValue - double
		text - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("PUT", "/order", params)
		return(data)


	def create_order(self, symbol, **OPargs):
		"""
		symbole - string
		side - string
		simpleOrderQty - double
		orderQty - double
		price - double
		displayQty - double
		stopPx - double
		clOrderID - string
		clOrderLinkID - string
		pegOffsetValue - double
		pegPriceType - string
		orderType - string
		timeInForce - string
		execInst - string
		contingencyType - string
		text - string
		"""
		params={"symbol":symbol}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/order", params)
		return(data)


	def cancel_order(self, **OPargs):
		"""
		orderID - string
		clOrdID - string
		text - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("DELETE", "/order", params)
		return(data)


	def cancel_all_orders(self, **OPargs):
		"""
		symbol - string
		filter - string
		text - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("DELETE", "/order/all", params)
		return(data)


	def amend_multi_orders(self, **OPargs):
		"""
		orders - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("PUT", "/order/bulk", params)
		return(data)


	def create_multi_orders(self, **OPargs):
		"""
		orders - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/order/bulk", params)
		return(data)


	def cancel_spec_orders(self, timeout):
		"""
		timeout - double
		"""
		params={"timeout":timeout}
		data = self.api_signed_request("POST", "/order/cancelAllAfter", params)
		return(data)


	def close_position(self, symbol, **OPargs):
		"""
		symbol - string
		price - double
		"""
		params={"symbol":symbol}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/order/closePosition", params)
		return(data)



	## OrderBook.
	def get_orderbook(self, symbol, **OPargs):
		"""
		symbol - string
		depth - double
		"""
		params={"symbol":symbol}
		params.update(OPargs)
		data = self.api_request("GET", "/orderBook/L2", params)
		return(data)



	## Position.
	def get_positions(self, **OPargs):
		"""
		filter - string
		columns - string
		count - double
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/position", params)
		return(data)


	def allow_isolated_margin(self, symbol, **OPargs):
		"""
		symbol - string
		enabled - boolean
		"""
		params={"symbol":symbol}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/position/isolate", params)
		return(data)


	def set_leverage(self, symbol, leverage):
		"""
		symbol - string
		leverage - double
		"""
		params={"symbol":symbol, "leverage":leverage}
		data = self.api_signed_request("POST", "/position/leverage", params)
		return(data)


	def update_risk(self, symbol, riskLimit):
		"""
		symbol - string
		riskLimit - double
		"""
		params={"symbol":symbol, "riskLimit":riskLimit}
		data = self.api_signed_request("POST", "/position/riskLimit", params)
		return(data)


	def transfer_equity(self, symbol, amount):
		"""
		symbol - string
		amount - double
		"""
		params={"symbol":symbol, "amount":amount}
		data = self.api_signed_request("POST", "/position/transferMargin", params)
		return(data)



	## Quote.
	def get_quotes(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/quote", params)
		return(data)


	def get_bucket_quotes(self, **OPargs):
		"""
		binSize - string
		partial - boolean
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/quote/bucketed", params)
		return(data)



	## Schema.
	def get_model_schemata_api(self, **OPargs):
		"""
		model - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/schema", params)
		return(data)


	def get_model_schemata_websocket(self):
		"""
		"""
		data = self.api_request("GET", "/schema/websocketHelp", {})
		return(data)



	## Settlement.
	def get_settlement(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/settlement", params)
		return(data)



	## Stats.
	def get_stats(self):
		"""
		"""
		data = self.api_request("GET", "/stats", {})
		return(data)


	def get_hist_stats(self):
		"""
		"""
		data = self.api_request("GET", "/stats/history", {})
		return(data)


	def get_summary_stats(self):
		"""
		"""
		data = self.api_request("GET", "/stats/historyUSD", {})
		return(data)



	## Trade.
	def get_trade(self, **OPargs):
		"""
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/trade", params)
		return(data)


	def get_bucket_trades(self, **OPargs):
		"""
		binSize - string
		partial - boolean
		symbol - string
		filter - string
		columns - string
		count - double
		start - double
		reverse - boolean
		startTime - date-time
		endTime - date-time
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/trade/bucketed", params)
		return(data)



	## User.
	def get_user(self):
		"""
		"""
		data = self.api_signed_request("GET", "/user", {})
		return(data)


	def update_user(self, **OPargs):
		"""
		oldPassword - string
		newPassword - string
		newPasswordConfirm - string
		username - string
		country - string
		pgpPubKey - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/user", params)
		return(data)


	def get_affiliate_status(self):
		"""
		"""
		data = self.api_signed_request("GET", "/user/affiliateStatus", {})
		return(data)


	def cancel_withdrawal(self, token):
		"""
		token - string
		"""
		params={"token":token}
		data = self.api_request("POST", "/user/cancel/Withdrawal", params)
		return(data)


	def check_referral_code(self):
		"""
		referralCode - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/user/checkReferralCode", params)
		return(data)


	def get_commission_stats(self):
		"""
		token - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/commission", params)
		return(data)


	def register_communication_token(self, token, platformAgent):
		"""
		token - string
		platformAgent - string
		"""
		params={"token":token, "platformAgent":platformAgent}
		data = self.api_signed_request("GET", "/user/communicationToken", params)
		return(data)


	def confirm_email(self, token, **OPargs):
		"""
		type - string
		token - string
		"""
		params={"token":token}
		params.update(OPargs)
		data = self.api_request("POST", "/user/confirmEmail", params)
		return(data)


	def confirm_tfa(self, token, **OPargs):
		"""
		type - string
		token - string
		"""
		params={"token":token}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/user/confirmEnableTFA", params)
		return(data)


	def confirm_withdrawal(self, token):
		"""
		token - string
		"""
		params={"token":token}
		data = self.api_request("POST", "/user/confirmWithdrawal", params)
		return(data)


	def get_deposit_address(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/depositAddress", params)
		return(data)


	def disable_tfa(self, token, **OPargs):
		"""
		type - string
		token - string
		"""
		params={"token":token}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/user/disableTFA", params)
		return(data)


	def get_execution_history(self, symbol, timestamp):
		"""
		symbol - string
		timestamp - date-time
		"""
		params={"symbol":symbol, "timestamp":timestamp}
		data = self.api_signed_request("GET", "/user/executionHistory", params)
		return(data)


	def user_logout(self):
		"""
		"""
		data = self.api_request("POST", "/user/logout", {})
		return(data)


	def all_logout(self):
		"""
		"""
		data = self.api_signed_request("POST", "/user/logoutAll", {})
		return(data)


	def get_margin_status(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/margin", params)
		return(data)


	def get_withdrawal_fee(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_request("GET", "/user/minWithdrawalFee", params)
		return(data)


	def save_user_preferences(self, prefs, **OPargs):
		"""
		prefs - string
		overwrite - boolean
		"""
		params={"prefs":prefs}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/user/preferences", params)
		return(data)


	def request_tfa(self, **OPargs):
		"""
		type - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("POST", "/user/requestEnableTFA", params)
		return(data)


	def request_withdrawal(self, currency, amount, address, **OPargs):
		"""
		otpToken - string
		currency - string
		amount - double
		address - string
		fee - double
		"""
		params={"currency":currency, "amount":amount, "address":address}.update(OPargs)
		data = self.api_signed_request("POST", "/user/requestWithdrawal", params)
		return(data)


	def get_wallet(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/wallet", params)
		return(data)


	def get_wallet_hist(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/walletHistory", params)
		return(data)


	def get_wallet_sum(self, **OPargs):
		"""
		currency - string
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/user/walletSummary", params)
		return(data)



	## User Event.
	def get_user_events(self, **OPargs):
		"""
		count - double
		start - double
		"""
		params={}
		params.update(OPargs)
		data = self.api_signed_request("GET", "/userEvent", params)
		return(data)



	def api_request(self, method, path, params=None):
		"""
		This is used for basic API requests.
		"""
		query = ""
		if params != None and params != {}:
			encodedParams = urlencode(sorted(params.items()))
			query = "?{0}".format(encodedParams)


		fullURL = "{0}{1}{2}".format(self.BASE_URL, path, query)

		apiResponse = requests.request(method, fullURL)

		data = apiResponse.json()

		return(data)


	def api_signed_request(self, method, path, params=None):
		"""
		This is used to get signed API requests
		"""
		query = ""
		if self.api_key == '' or self.api_secret == '':
			raise ValueError("Make sure you entered your API key/secret")

		if params != None and params != {}:
			encodedParams = urlencode(sorted(params.items()))
			query = "?{0}".format(encodedParams)

		nonce = int(round(time.time()) + 5)
		fullURL = bytes("{0}{1}{2}".format(self.BASE_URL, path, query), 'utf-8')
		signURL = bytes('{0}/api/v1{1}{2}{3}'.format(method, path, query, nonce), 'utf-8')

		signature = hmac.new(bytes(self.api_secret, 'utf-8'), signURL, digestmod=hashlib.sha256).hexdigest()
	
		headers = {
			"api-nonce":str(nonce),
			"api-key":self.api_key,
			"api-signature":signature
		}

		apiResponse = requests.request(method, fullURL, headers=headers)
		data = apiResponse.json()
					
		return(data)


