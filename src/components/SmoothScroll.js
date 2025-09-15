// SmoothScroll.js
export default class SmoothScroll {
	constructor(options = {}) {
		this.ease = options.ease || 0.08;
		this.enabled = !this.isTouchDevice(); // solo activo si no es touch
		this.currentScroll = window.scrollY;
		this.targetScroll = window.scrollY;
		this.isDragging = false;
		this.isPointerDown = false;

		if (this.enabled) {
			this.init();
		}
	}

	isTouchDevice() {
		return (
			"ontouchstart" in window ||
			navigator.maxTouchPoints > 0 ||
			navigator.msMaxTouchPoints > 0
		);
	}

	init() {
		this.updateScroll();
		this.addWheelListener();
		this.addDragListener();
		this.addScrollSync();
	}

	updateScroll = () => {
		if (!this.isDragging) {
			const delta = this.targetScroll - this.currentScroll;
			this.currentScroll += delta * this.ease;

			// Forzar que no pase del scroll máximo
			const maxScroll =
				document.documentElement.scrollHeight - window.innerHeight;
			if (this.currentScroll > maxScroll) this.currentScroll = maxScroll;

			window.scrollTo(0, this.currentScroll);
		} else {
			this.currentScroll = window.scrollY;
			this.targetScroll = this.currentScroll;
		}
		requestAnimationFrame(this.updateScroll);
	};

	addWheelListener() {
		window.addEventListener(
			"wheel",
			(e) => {
				if (!this.isDragging) {
					e.preventDefault();
					const scaledDelta = e.deltaY * 0.5;
					this.targetScroll += scaledDelta;

					const maxScroll =
						document.documentElement.scrollHeight - window.innerHeight;
					this.targetScroll = Math.max(
						0,
						Math.min(this.targetScroll, maxScroll),
					);
				}
			},
			{ passive: false },
		);
	}

	addDragListener() {
		window.addEventListener("mousedown", (e) => {
			if (e.offsetX > document.documentElement.clientWidth - 20) {
				this.isDragging = true;
				this.isPointerDown = true;
			}
		});

		window.addEventListener("mouseup", () => {
			if (this.isPointerDown) {
				this.isDragging = false;
				this.isPointerDown = false;
			}
		});
	}

	addScrollSync() {
		window.addEventListener("scroll", () => {
			if (this.isDragging) {
				this.currentScroll = window.scrollY;
				this.targetScroll = this.currentScroll;
			}
		});
	}
}
