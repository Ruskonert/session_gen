use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Poll<T> {
    data: Vec<T>,
    per_seconds: u128,
    pub loop_count: usize,

    maximum: usize,
    nano_duration: u128,

    // Internal only, please don't modify belows.
    idx: usize,
    loop_intl: usize,
    build_time: Instant,
    instant_time: Instant,
    ended: bool,
    reset: bool,
}

impl<T> Default for Poll<T> {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            data: Vec::new(),
            instant_time: now,
            per_seconds: 1e+9 as u128,
            loop_count: 1,
            maximum: 0,
            nano_duration: 0,
            idx: 0,
            loop_intl: 0,
            build_time: now,
            ended: false,
            reset: false,
        }
    }
}

impl<T: Default> Poll<T> {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn poll(&mut self) -> Option<T>
    where
        T: ToOwned<Owned = T>,
    {
        if !self.ended {
            let end_time = Instant::now();
            let elapsed_time = end_time.duration_since(self.instant_time);
            let nanos = elapsed_time.as_nanos();

            return if nanos >= self.nano_duration {
                let payload = self.data[self.idx].to_owned();
                self.instant_time = end_time;
                self.idx += 1;

                if self.idx == self.maximum {
                    self.idx = 0;
                    self.loop_intl += 1;
                    self.reset = true;
                } else {
                    if self.reset {
                        self.reset = false;
                    }
                }

                if self.loop_count > 0 {
                    if self.loop_intl >= self.loop_count {
                        self.ended = true;
                    }
                }
                Some(payload)
            } else {
                None
            };
        }
        None
    }

    pub fn push_data(&mut self, element: T) {
        self.data.push(element);
    }

    pub fn clear_data(&mut self) {
        self.data.clear();
    }

    pub fn set_data(&mut self, element: T, idx: usize) {
        self.data.insert(idx, element);
    }

    pub fn set_per_second(&mut self, per_seconds: f64) {
        self.per_seconds = Duration::from_secs_f64(1.0 / per_seconds).as_nanos();
    }

    pub fn is_ended(&self) -> bool {
        self.ended
    }

    pub fn is_reset(&self) -> bool {
        self.reset
    }

    pub fn build(&mut self) {
        let current_time = Instant::now();

        self.check_invaild();

        self.nano_duration = self.per_seconds;
        self.build_time = current_time;
        self.instant_time = current_time;
        self.idx = 0;
        self.maximum = self.data.len();
        self.ended = false;
        self.reset = false;
        self.loop_intl = 0;
    }

    fn check_invaild(&mut self) {
        if self.per_seconds == 0 {
            self.set_per_second(1.0);
        }
        if self.data.len() == 0 {
            // nothing!
        }
    }
}

#[cfg(test)]
mod test {
    use super::Poll;
    use std::{str::from_utf8_unchecked, time::SystemTime};

    #[test]
    pub fn test_poll() {
        let mut poll: Poll<Vec<u8>> = Poll::new();
        poll.set_per_second(3.0);
        poll.loop_count = 3;

        poll.push_data("Hello world".as_bytes().to_vec());
        poll.push_data("Hello world2".as_bytes().to_vec());
        poll.push_data("Hello world3".as_bytes().to_vec());
        poll.build();

        let time = SystemTime::now();
        while !poll.is_ended() {
            while let Some(v) = poll.poll() {
                println!(
                    "elapsed = {:?}, output = {:?}",
                    time.elapsed().unwrap(),
                    unsafe { from_utf8_unchecked(&v) }
                );
            }
        }
        assert_eq!(time.elapsed().unwrap().as_secs(), 3);
    }
}
