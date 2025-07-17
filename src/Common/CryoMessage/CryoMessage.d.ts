export type Cryo_SystemMessageIdentifier = "error" | "success";
export type Cryo_ClientMessageIdentifier = "subscribe" | "unsubscribe" | "data" | "mktopic" | "rmtopic";
export type Cryo_ServerMessageIdentifier = "shutdown";
export type Cryo_AllMessageIdentifier = Cryo_SystemMessageIdentifier | Cryo_ClientMessageIdentifier | Cryo_ServerMessageIdentifier;

export type CryoMessage<T, U extends AllMessageType> = {
    type: U;
    timestamp: number;
} & T;

export type CryoErrorMessage = CryoMessage<{
    message: string;
}, "error">

export type CryoSuccessMessage = CryoMessage<{
    message: string;
}, "success">

export type CryoSubscriptionMessage = CryoMessage<{
    subscribe_to: string;
}, "subscribe">;

export type CryoUnsubscribeMessage = CryoMessage<{
    unsubscribe_from: string;
}, "unsubscribe">;

export type CryoDataMessage = CryoMessage<{
    data: any;
    topic: string;
}, "data">;

export type CryoShutdownMessage = CryoMessage<{
    reason: string;
    topic: string;
}, "shutdown">;

export type CryoMakeTopicMessage = CryoMesage<{
    create_topic: string;
}, "mktopic">;

export type CryoRemoveTopicMessage = CryoMessage<{
    remove_topic: string;
}, "rmtopic">;


export type CryoSystemMessage = CryoSuccessMessage | CryoErrorMessage;
export type CryoClientMessage = CryoSubscriptionMessage | CryoUnsubscribeMessage | CryoDataMessage | CryoMakeTopicMessage | CryoRemoveTopicMessage;
export type CryoServerMessage = CryoShutdownMessage;

export type CryoAllMessage = CryoSystemMessage | CryoClientMessage | CryoServerMessage;