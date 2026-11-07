python test_suite.py
python node.py bob
python -c "import asyncio; from node import ConsortiumNode; node = ConsortiumNode('alice'); asyncio.run(node.send_asymmetric_message('bob', 'Hello Bob, consortium node online!'))"