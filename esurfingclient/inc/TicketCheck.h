#ifndef ESURFINGCLIENT_TICKETCHECK_H
#define ESURFINGCLIENT_TICKETCHECK_H

/**
 * @brief 进入 Ticket 获取检查流程
 */
void ticket_check_run(void);

/**
 * @brief 指定稳定 Algo-ID 获取 Ticket（只接受服务端下发的同 ID ZSM）
 */
void ticket_direct_run(void);

/**
 * @brief 固定一个 Algo-ID，轮询现有算法实现直到换到 Ticket
 */
void ticket_algo_poll_run(void);

#endif // ESURFINGCLIENT_TICKETCHECK_H
