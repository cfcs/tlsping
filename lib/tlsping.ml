type client_operation =
| Connect
| Outgoing
| Queue
| Ack
| Status
| Fetch
| Subscribe

type server_operation =
| Connect_answer
| Status_answer
| Incoming


