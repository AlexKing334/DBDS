import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CircuitBreaker:
    def __init__(self, nome):
        self.TEMPO_RIAPERURA_AUTOMATICA = 30
        self.circuit_breaker = False
        self.nome = nome

    def get_name(self):
        return self.nome

    def callback_open_circuit_breaker(self, retry_state):
        if not self.circuit_breaker:
            logger.info(f"Circuit Breaker {self.get_name()} aperto")
            self.circuit_breaker = True
            self.callback_closed_circuit_breaker()

    def callback_closed_circuit_breaker(self):
        if self.circuit_breaker:
            logger.info(f"Circuit Breaker {self.get_name()} - start countdown")
            time.sleep(self.TEMPO_RIAPERURA_AUTOMATICA)
            logger.info(f"Circuit Breaker chiuso {self.get_name()} - finish countdown")
            self.circuit_breaker = False

    def is_circuit_breaker_open(self):
        return self.circuit_breaker
