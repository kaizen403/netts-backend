import { Kafka } from "kafkajs";
import { broadcastBatteryData } from "../socket/socketServer.js";

const kafka = new Kafka({
  clientId: "battery-consumer",
  brokers: ["localhost:9092"],
});

const consumer = kafka.consumer({ groupId: "battery-group" });

// Removed 'io' parameter since it's not used in the function
export async function startConsumer() {
  await consumer.connect();
  await consumer.subscribe({ topic: "batterydetails", fromBeginning: true });

  await consumer.run({
    // Destructure only the needed 'message'
    eachMessage: async ({ message }) => {
      const data = JSON.parse(message.value.toString());
      broadcastBatteryData(data);
    },
  });
}
