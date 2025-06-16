import pprint

#example input
input_data = {
    "usernames": ["Torin", "Quinn", "Noah", "Liam"],
    "passwords": ["PW1", "PW2", "PW3"],
    "protocols": ["PEAP/MSCHAPV2", "TLS"]
}

output = []
protocol_counts = {}

for username in input_data["usernames"]:
    for password in input_data["passwords"]:
        for protocol in input_data["protocols"]:
            if "/" in protocol:
                outer, inner = protocol.split("/", 1)
                entry = {
                    "username": username,
                    "password": password,
                    "outer_protocol": outer,
                    "inner_protocol": inner
                }
                protocol_counts[outer] = protocol_counts.get(outer, 0) + 1
                protocol_counts[inner] = protocol_counts.get(inner, 0) + 1
            else:
                entry = {
                    "username": username,
                    "password": password,
                    "protocol": protocol
                }
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
            output.append(entry)

pprint.pprint(output)
print("\nProtocol counts:")
for proto, count in protocol_counts.items():
    print(f"{proto}: {count}")