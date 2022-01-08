#need to first check balance, but need sim network for this first

'''
Finalized/Standard transactions MUST:

1) Locktime must be in the past *less than or equal to the current block height*, or all of its sequence numbers must be 0xffffffff. *No lock time
2) TrX < 100,000 bytes
3) transaction’s signature scripts < 1,650 bytes
4) Transaction’s signature script must only push data to the script evaluation stack *NO new OPCodes*
5) Transactions must not include outputs w/ < 1/3 as many satoshis as it would take to spend it in a typical input.  **That’s currently 546 satoshis for a P2PKH or P2SH output on a Bitcoin Core node with the default relay fee. Exception: standard null data outputs must receive zero satoshis **
*Bare (non-P2SH) multisig transactions which require more than 3 public keys are currently non-standard*
'''

'''
DECODED TrX:
{
  "version": 1,
  "locktime": 0,
  "vin": [
    {
      "txid": "7957a35fe64f80d234d76d83a2a8f1a0d8149a41d81de548f0a65a8a999f6f18",
      "vout": 0,
      "scriptSig" : "3045022100884d142d86652a3f47ba4746ec719bbfbd040a570b1deccbb6498c75c4ae24cb02204b9f039ff08df09cbe9f6addac960298cad530a863ea8f53982c09db8f6e3813[ALL] 0484ecc0d46f1918b30928fa0e4ed99f16a0fb4fde0735e7ade8416ab9fe423cc5412336376789d172787ec3457eee41c04f4938de5cc17b4a10fa336a8d752adf",
      "sequence": 4294967295
    }
  ],
  "vout": [
    {
      "value": 0.01500000,
      "scriptPubKey": "OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value": 0.08450000,
      "scriptPubKey": "OP_DUP OP_HASH160 7f9b1a7fb68d60c536c2fd8aeaa53a8f3cc025a8 OP_EQUALVERIFY OP_CHECKSIG",
    }
  ]
}
'''


class TrX:

    def __init__(self, amount, recipient_list, version = 1, locktime = 0):
        # utxos(TrX objs) will become the vin for the transaction
        self.utxo_list = []
        #Version is 4bytes that tells peers/miners which set of rules the TrX follows / TrX w/ BIP68 have version 2 *new*
        self.version = version
        self.locktime = locktime     #locktime and sequence are directly related *sequence within in vin
        self.amount = amount
        #recipient's address may be --> P2PKH / P2WPKH / P2SH / P2WSH    * see NOTES for address prefixes *
        self.recipient_list = recipient_list


    # 1 --> aggregate available utxos to spend
    def find_utxos_toSpend():
        utxo = []
        # call balance tracker to find largest utxo available
        largest_utxo = balance_tracker.get_largest_utxo()
        if(self.amount <= largest_utxo)
            #trx will be a common/distributing 
            construct_trx(largest_utxo)
        else 
            # trx will be aggregating
            gather_sufficient_utxos()

    def gather_sufficient_utxos():
        #run algo to find sufficient utxos to build desired transaction
        print(0)


    # 2 --> construct transaction
    #  



'''
NOTES:

Address Pre fixes:     ** l = legacy 
- P2PKH --> 1 or (l) m/n
- P2WPKH -> 3
- P2SH  --> 3 or (l) 2
- P2WSH --> 3 or (testnet) tb1 or (native segwit) bc1
'''





