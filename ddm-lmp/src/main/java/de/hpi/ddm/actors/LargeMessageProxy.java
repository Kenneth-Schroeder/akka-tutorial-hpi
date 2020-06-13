package de.hpi.ddm.actors;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.UUID;

import akka.actor.*;
import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import de.hpi.ddm.structures.KryoPoolSingleton;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class LargeMessageProxy extends AbstractLoggingActor {

	////////////////////////
	// Actor Construction //
	////////////////////////

	public static final String DEFAULT_NAME = "largeMessageProxy";
	public static final int CHUNK_SIZE = 1024 * 64; // 64 kb
	
	public static Props props() {
		return Props.create(LargeMessageProxy.class);
	}

	////////////////////
	// Actor Messages //
	////////////////////
	
	@Data @NoArgsConstructor @AllArgsConstructor
	public static class LargeMessage<T> implements Serializable {
		private static final long serialVersionUID = 2940665245810221108L;
		private T message;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class BytesMessage<T> implements Serializable {
		private static final long serialVersionUID = 4057807743872319842L;
		private T bytes;
		private ActorRef sender;
		private ActorRef receiver;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class TransferMetadata implements Serializable {
		private static final long serialVersionUID = 6076779341642038282L;
		private ActorRef sender;
		private ActorRef receiver;
		private String transferID;
		private boolean done;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class Transfer implements Serializable {
		private static final long serialVersionUID = 1180264267478444181L;
		private byte[] bytes;
		private String transferID;
		private int chunkNo;
		private int totalSize;
	}

	@Data @NoArgsConstructor @AllArgsConstructor
	public static class RequestChunk implements Serializable {
		private static final long serialVersionUID = 1669915847159270077L;
		private String transferID;
		private int chunkNo;
	}

	private static class OutgoingTransfer {
		private final byte[] data;
		public OutgoingTransfer(byte[] data) {
			this.data = data;
		}
		public int NumChunks() {
			return (int) Math.ceil((double)data.length / CHUNK_SIZE);
		}
		public byte[] GetChunk(int chunkNo) {
			int from = chunkNo * CHUNK_SIZE;
			int to = from + CHUNK_SIZE;
			if(to >= data.length) {
				to = data.length;
			}
			return Arrays.copyOfRange(data, from, to);
		}
		public int size() {
			return this.data.length;
		}
	}

	private static class IncomingTransfer {
		private final ByteArrayOutputStream data = new ByteArrayOutputStream();
		private int chunksReceived = 0;
		private ActorRef receiver;
		private ActorRef sender;
		IncomingTransfer(ActorRef aReceiver, ActorRef aSender) {
			receiver = aReceiver;
			sender = aSender;
		}
		public ActorRef getReceiver() {
			return receiver;
		}
		public ActorRef getSender() {
			return sender;
		}
		public void AddChunk(byte[] buf) throws IOException {
			data.write(buf);
			chunksReceived++;
		}
		public int BytesReceived() {
			return data.size();
		}
		public byte[] Data() {
			return data.toByteArray();
		}
	}

	private HashMap<String, OutgoingTransfer> outgoing = new HashMap<>();
	private HashMap<String, IncomingTransfer> incoming = new HashMap<>();
	
	/////////////////
	// Actor State //
	/////////////////
	
	/////////////////////
	// Actor Lifecycle //
	/////////////////////

	////////////////////
	// Actor Behavior //
	////////////////////
	
	@Override
	public Receive createReceive() {
		return receiveBuilder()
				.match(LargeMessage.class, this::handle)
				.match(BytesMessage.class, this::handle)
				.match(TransferMetadata.class, this::handle)
				.match(RequestChunk.class, this::handle)
				.match(Transfer.class, this::handle)
				.matchAny(object -> this.log().info("Received unknown message: \"{}\"", object.toString()))
				.build();
	}

	private void handle(Transfer message) {
		if(!incoming.containsKey(message.transferID)) return;
		IncomingTransfer t = incoming.get(message.transferID);
		this.log().info(String.format("Received chunk %d of transfer with ID %s.", message.chunkNo, message.transferID));
		try {
			t.AddChunk(message.bytes);
		} catch (IOException e) {
			e.printStackTrace();
		}
		if(t.BytesReceived() == message.totalSize) {
			this.log().info(String.format("Transfer %s complete, now deserialization and dispatching ...", message.transferID));
			TransferMetadata m = new TransferMetadata();
			m.done = true;
			m.transferID = message.transferID;
			this.sender().tell(m, this.self());

			// Deserialize:
//			Kryo k = new Kryo();
//			Input inp = new Input(t.Data());
//			Object result = k.readClassAndObject(inp);
//			Object result = null;
//			try {
//				ObjectInputStream objectin = new ObjectInputStream(new ByteArrayInputStream(t.Data()));
//				result = objectin.readObject();
//			} catch (IOException | ClassNotFoundException e) {
//				e.printStackTrace();
//			}

			Object result = KryoPoolSingleton.get().fromBytes(t.Data());
			if(result != null) {
				ActorRef originalReceiver = t.getReceiver();
				ActorRef originalSender = t.getSender();
				originalReceiver.tell(result, originalSender);
			} else {
				this.log().info(String.format("Deserialization of Transfer %s yielded NULL?!", message.transferID));
			}

			// Clean up
			incoming.remove(message.transferID);
		} else {
			this.sender().tell(new RequestChunk(message.transferID, message.chunkNo+1), this.self());
		}
	}

	private void handle(RequestChunk message) {
		if(!outgoing.containsKey(message.transferID)) return;
		OutgoingTransfer t = outgoing.get(message.transferID);
		this.sender().tell(new Transfer(
				t.GetChunk(message.chunkNo),
				message.transferID,
				message.chunkNo,
				t.size()), this.self());
	}

	private void handle(TransferMetadata message) {
		if(message.done) { // Delete ongoing message transfer
			outgoing.remove(message.transferID);
			this.log().info(String.format("Transfer ID %s completed.", message.transferID));
			return;
		}

		// Else we can request chunks now
		this.log().info(String.format("Start receiving message with ID %s.", message.transferID));
		incoming.put(message.transferID, new IncomingTransfer(message.receiver, message.sender));
		this.sender().tell(new RequestChunk(message.transferID, 0), this.self());
	}

	private void handle(LargeMessage<?> message) {
		ActorRef receiver = message.getReceiver();
		ActorSelection receiverProxy = this.context().actorSelection(receiver.path().child(DEFAULT_NAME));
		
		// This will definitely fail in a distributed setting if the serialized message is large!
		// Solution options:
		// 1. Serialize the object and send its bytes batch-wise (make sure to use artery's side channel then).
		// 2. Serialize the object and send its bytes via Akka streaming.
		// 3. Send the object via Akka's http client-server component.
		// 4. Other ideas ...

//		Kryo k = new Kryo();
//		Output out = new Output(new ByteArrayOutputStream());
//		k.writeClassAndObject(out, message.getMessage());
//		ByteArrayOutputStream byteout = new ByteArrayOutputStream();
//		try {
//			ObjectOutputStream objectout = new ObjectOutputStream(byteout);
//			objectout.writeObject(message.getMessage());
//			objectout.close();
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
		byte[] data = KryoPoolSingleton.get().toBytesWithClass(message.getMessage());
		String transferId = UUID.randomUUID().toString();
		outgoing.put(transferId, new OutgoingTransfer(data));

		TransferMetadata metaMessage = new TransferMetadata();
		metaMessage.transferID = transferId;
		metaMessage.sender = this.sender();
		metaMessage.receiver = message.getReceiver();
		metaMessage.done = false;
		this.log().info(String.format("New transfer (%d bytes) with ID %s available.", data.length, transferId));

		receiverProxy.tell(metaMessage, this.self());
//		receiverProxy.tell(new BytesMessage<>(message.getMessage(), this.sender(), message.getReceiver()), this.self());
	}

	private void handle(BytesMessage<?> message) {
		// Reassemble the message content, deserialize it and/or load the content from some local location before forwarding its content.
		message.getReceiver().tell(message.getBytes(), message.getSender());
	}
}
