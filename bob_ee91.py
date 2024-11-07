import socket
import pickle
import numpy as np
from qiskit import Aer, QuantumCircuit, execute
from qiskit.visualization import circuit_drawer
import time
import matplotlib.pyplot as plt
from auth import authenticate_party, passwd_entry

def authenticate_status():
    auth = authenticate_party("Doctor", "Bob", "192.168.56.1", "bob@5678")
    #print(f"Bob authentication status: {auth}")
    return auth

def generate_random_key(length):
    return ''.join(np.random.choice(['0', '1'], length))

def visualize_circuit(qc):
    circuit_drawer(qc, output='mpl', scale=0.7, plot_barriers=False, vertical_compression="low", style="iqp")
    plt.title("Bob's Quantum Circuit")
    plt.show()

def e91_protocol(client_socket):
    total_bits = 64

    # Receive Alice's entangled qubits
    received_data = b''
    while True:
        chunk = client_socket.recv(8192)
        received_data += chunk
        if len(chunk) < 8192:  # Last chunk received
            break
    alice_pairs = pickle.loads(received_data)
    print(f"Bob received entangled pairs")

    # Receive Alice's bases
    alice_bases = client_socket.recv(1024).decode()
    print(f"Bob received Alice's bases: {alice_bases}")

    # Generate random bases for Bob
    bob_bases = generate_random_key(total_bits)
    print(f"Bob's bases: {bob_bases}")
    print("--------------------------------------------------------\n")

    # Send Bob's bases to Alice
    client_socket.send(bob_bases.encode())

    # Measure Bob's qubits
    bob_measurement_results = []
    for i, pair in enumerate(alice_pairs):
        qc = QuantumCircuit(2, 2)
        # Apply received instruction to the new circuit
        qc.append(pair[0], [0, 1])
        # Apply Hadamard gate conditionally
        if bob_bases[i] != alice_bases[i]:
            qc.h(1)
        qc.measure(0, 0)  # Measure qubit
        job = execute(qc, Aer.get_backend('qasm_simulator'), shots=1)
        result = job.result()
        counts = result.get_counts()
        measurement_result = '0' if list(counts.keys())[0] == '0' else '1'
        bob_measurement_results.append(measurement_result)

    # Visualize the circuit after measurement
    #visualize_circuit(qc)

    # Interpret results based on matching bases
    bob_interpreted_results = ''
    for i in range(total_bits // 2):
        # Check if Bob's base matches Alice's received base
        if bob_bases[i] == alice_bases[i]:
            # No change if bases match
            bob_interpreted_results += bob_measurement_results[i]
        else:
            # Invert if bases differ
            bob_interpreted_results += '1' if bob_measurement_results[i] == '0' else '0'

    # Extract the key from all shared qubits based on matching bases
    final_key = ''
    for i in range(total_bits // 2):
        final_key += bob_interpreted_results[i]

    return final_key

def main():
    # Create a socket and listen for incoming connections
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12346))
    server_socket.listen(1)
    print("Waiting for Alice...")
    client_socket, client_address = server_socket.accept()
    status_bob = authenticate_status()
    status = client_socket.recv(1024).decode()
    client_socket.send(status_bob.encode())

    total_runs = 5 # Number of runs to perform

    accumulated_key = ''

    keys = []
    if status == "1":
        for _ in range(total_runs):
            client_socket, client_address = server_socket.accept()
            # Run the E91 protocol as Bob for each iteration
            final_key = e91_protocol(client_socket)
            keys.append(final_key)
            # Accumulate the keys
            accumulated_key += final_key
            client_socket.close()
    else:
        print("DEVICE ERROR!!!")

    print(f"Secret key formed by the combination of :{keys}")

    # Print or use accumulated_key, average_secret_key_rate, average_eavesdropping_prob
    print("\n")
    print("RESULTS: \n")
    print(f"Accumulated Key: {accumulated_key} ({len(accumulated_key)})")

    with open("final_key_bob.txt", "wb") as key_file:
        key_file.write(accumulated_key.encode())
    print("Key saved in file")

    server_socket.close()


if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    time = end_time - start_time
    print(f"Time required: {time:.2f} s")