# Things that the network needs to do:
# 1. Store a ledger
# 2. Write user transactions to the ledger
# 3. Generate transactions on the ledger
# 4. Find transactions on the ledger given a bloom filter
#
#
# The Ledger: 2 options here
#   1. Copy the design fundamentals of a blockchain ledger
#   2. Make the ledger simply a file containing a large collection of transactions. As they are spent, the network can mark them as spent and track UTXO's as unmarked transactions
#
#
# Ledger is just a file.
# Writing user transactions is writing to that file and marking the now spent UTXO's.
# Generating transactions can just be generating a random key & building a transaction(s) from it.
# Finding transactions will be pattern matching against the UTXO set in the ledger. Python probably has something easy for this without getting too complex.