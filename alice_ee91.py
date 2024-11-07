import time
import socket
import pickle
import numpy as np
from qiskit import QuantumCircuit, Aer, execute
from qiskit.visualization import circuit_drawer
import matplotlib.pyplot as plt
from auth import authenticate_party, passwd_entry

def authenticate_status():
    auth = authenticate_party("Doctor", "Alice", "192.168.56.1", "alice@1234")
    #print(f"Alice authentication status: {auth}")
    return auth

def generate_random_key(length):
    return ''.join(np.random.choice(['0', '1'], length))

def generate_entangled_pair():
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.measure([0, 1], [0, 1])  # Measure Alice's qubits
    return qc

def visualize_circuit(qc):
    circuit_drawer(qc, output='mpl', scale=0.7, plot_barriers=False, vertical_compression="low", style="iqp")
    plt.title("Alice's Quantum Circuit")
    plt.show()

def e91_protocol(client_socket):
    total_bits = 64

    # Generate entangled pairs
    alice_pairs = [generate_entangled_pair() for _ in range(total_bits // 2)]
    

    target_qubits = [pair[1] for pair in alice_pairs]
    control_qubits = [pair[0] for pair in alice_pairs]
    # Serialize the circuit to send over the communication channel
    serialized_pairs = pickle.dumps(target_qubits)
    chunks = [serialized_pairs[i:i + 8192] for i in range(0, len(serialized_pairs), 8192)]
    for chunk in chunks:
        client_socket.send(chunk)
    print(f"Alice sent her entangled pairs")
    

    alice_bases = generate_random_key(total_bits)
    client_socket.send(alice_bases.encode())
    print(f"Alice sent her bases: {alice_bases}")

    # Receive Bob's bases
    bob_bases = client_socket.recv(1024).decode()
    print(f"Alice received Bob's bases: {bob_bases}")
    print("--------------------------------------------------------\n")

    # Measure Alice's qubits based on her bases
    alice_measurement_results = ''
    for i, pair in enumerate(control_qubits):
        qc = QuantumCircuit(2, 2)
        # Apply received instruction to the new circuit
        qc.append(pair[0], [0])
        qc.measure(0, 0)  # Measure qubit
        job = execute(qc, Aer.get_backend('qasm_simulator'), shots=1)
        result = job.result()
        counts = result.get_counts()
        measurement_result = '0' if list(counts.keys())[0] == '0' else '1'
        alice_measurement_results += measurement_result

    #visualize_circuit(qc)

    # Interpret results based on matching bases
    alice_interpreted_results = ''
    for i in range(total_bits // 2):
        # Check if Alice's base matches Bob's received base
        if alice_bases[i] == bob_bases[i]:
            # No change if bases match
            alice_interpreted_results += alice_measurement_results[i]
        else:
            # Invert if bases differ
            alice_interpreted_results += '1' if alice_measurement_results[i] == '0' else '0'

    # Compare Alice's and Bob's bases and extract common qubits
    final_key = ''
    for i in range(total_bits // 2):
        final_key += alice_interpreted_results[i]

    return final_key


def main():
    # Connect to Bob over a secure socket
    server_address = ('localhost', 12346)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    status_alice = authenticate_status()
    client_socket.send(status_alice.encode())
    #print(f"Sent status  {status_alice}")
    status = client_socket.recv(1024).decode()
    #print(f"Received status..{status}")
    client_socket.close()

    total_runs = 5  # Number of runs to perform

    accumulated_key = ''

    if status == "1":
        keys = []
        for _ in range(total_runs):
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(server_address)
            # Run the E91 protocol as Alice for each iteration
            final_key = e91_protocol(client_socket)
            keys.append(final_key)
            # Accumulate the keys
            accumulated_key += final_key
            # After each iteration, close the socket
            client_socket.close()
    else:
        print("DEVICE ERROR!!!")

    print(f"Secret key formed by the combination of :{keys}")
    print("\n")
    print("RESULTS: \n")
    print(f"Accumulated Key: {accumulated_key} ({len(accumulated_key)})")

    with open("final_key_alice.txt", "wb") as key_file:
        key_file.write(accumulated_key.encode())
    print("Key saved in file")


if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    time = end_time - start_time
    print(f"Time required: {time:.2f} s")