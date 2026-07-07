package main

import (
	"bufio"
	"context"
	"fmt"
	"image/color"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type processRunner struct {
	mu            sync.Mutex
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	stopRequested bool
}

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (r *processRunner) isRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmd != nil
}

func (r *processRunner) start(command string, args []string, onLine func(string), onExit func(error)) error {
	r.mu.Lock()
	if r.cmd != nil {
		r.mu.Unlock()
		return fmt.Errorf("process is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	if err = cmd.Start(); err != nil {
		cancel()
		r.mu.Unlock()
		return err
	}
	r.cmd = cmd
	r.cancel = cancel
	r.stopRequested = false
	r.mu.Unlock()

	go streamOutput(stdout, onLine)
	go streamOutput(stderr, onLine)
	go func() {
		errWait := cmd.Wait()
		r.mu.Lock()
		r.cmd = nil
		r.cancel = nil
		r.mu.Unlock()
		onExit(errWait)
	}()
	return nil
}

func (r *processRunner) stop() {
	r.mu.Lock()
	cmd := r.cmd
	cancel := r.cancel
	r.stopRequested = true
	r.mu.Unlock()

	if cmd != nil && cmd.Process != nil && strings.EqualFold(os.Getenv("OS"), "Windows_NT") {
		_ = exec.Command("taskkill", "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	}
	if cancel != nil {
		cancel()
	}
}

func (r *processRunner) wasStopRequested() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopRequested
}

func streamOutput(reader io.Reader, onLine func(string)) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		onLine(scanner.Text())
	}
}

func appendLog(logBox *widget.Entry, line string) {
	timePrefix := time.Now().Format("15:04:05")
	cleanLine := ansiEscapePattern.ReplaceAllString(line, "")
	logBox.SetText(logBox.Text + "[" + timePrefix + "] " + cleanLine + "\n")
}

func parsePositiveInt(fieldName string, text string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", fieldName)
	}
	return value, nil
}

func main() {
	if strings.EqualFold(os.Getenv("OS"), "Windows_NT") && strings.TrimSpace(os.Getenv("FYNE_SCALE")) == "" {
		_ = os.Setenv("FYNE_SCALE", "1")
	}

	a := app.New()
	w := a.NewWindow("HEP Sender")
	w.Resize(fyne.NewSize(680, 620))

	senderRunner := &processRunner{}
	statusLabel := widget.NewLabel("Ready")
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	stateBg := canvas.NewRectangle(color.NRGBA{R: 99, G: 102, B: 106, A: 255})
	stateBg.SetMinSize(fyne.NewSize(220, 42))
	stateTitle := canvas.NewText("Sender", color.White)
	stateTitle.TextStyle = fyne.TextStyle{Bold: true}
	stateText := canvas.NewText("Idle", color.White)
	stateText.TextStyle = fyne.TextStyle{Bold: true}
	stateCard := container.NewMax(
		stateBg,
		container.NewPadded(container.NewHBox(stateTitle, canvas.NewText(": ", color.White), stateText)),
	)
	updateState := func(state string, bgColor color.Color) {
		stateBg.FillColor = bgColor
		stateBg.Refresh()
		stateText.Text = state
		stateText.Refresh()
	}

	logBox := widget.NewMultiLineEntry()
	logBox.SetMinRowsVisible(16)
	logBox.Wrapping = fyne.TextWrapWord

	senderTLS := widget.NewCheck("Enable TLS (-tls)", nil)
	senderDetail := widget.NewCheck("Detail log (-dl)", nil)
	senderChecks := container.NewHBox(senderTLS, senderDetail)

	senderProtocol := widget.NewSelect([]string{"tcp", "udp"}, nil)
	senderProtocol.SetSelected("tcp")
	senderIP := widget.NewEntry()
	senderIP.SetText("127.0.0.1")
	senderPort := widget.NewEntry()
	senderPort.SetText("9889")
	senderMsgNum := widget.NewEntry()
	senderMsgNum.SetText("5")
	senderInterval := widget.NewEntry()
	senderInterval.SetText("1000000")
	senderThreads := widget.NewEntry()
	senderThreads.SetText("1")

	startSender := widget.NewButtonWithIcon("Start Sender", theme.MediaPlayIcon(), func() {
		if senderRunner.isRunning() {
			statusLabel.SetText("Sender is already running")
			updateState("Already running", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
			return
		}

		mn, err := parsePositiveInt("message number", senderMsgNum.Text)
		if err != nil {
			statusLabel.SetText(err.Error())
			return
		}
		rn, err := parsePositiveInt("interval (microseconds)", senderInterval.Text)
		if err != nil {
			statusLabel.SetText(err.Error())
			return
		}
		tn, err := parsePositiveInt("thread number", senderThreads.Text)
		if err != nil {
			statusLabel.SetText(err.Error())
			return
		}

		args := []string{
			"run", "hepSender.go",
			"-tu", strings.TrimSpace(senderProtocol.Selected),
			"-da", strings.TrimSpace(senderIP.Text),
			"-dp", strings.TrimSpace(senderPort.Text),
			"-mn", strconv.Itoa(mn),
			"-rn", strconv.Itoa(rn),
			"-tn", strconv.Itoa(tn),
		}
		if senderTLS.Checked {
			args = append(args, "-tls")
		}
		if senderDetail.Checked {
			args = append(args, "-dl")
		}

		statusLabel.SetText("Starting sender...")
		updateState("Starting", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
		appendLog(logBox, "Start sender: go "+strings.Join(args, " "))

		err = senderRunner.start(
			"go",
			args,
			func(line string) { appendLog(logBox, "[sender] "+line) },
			func(exitErr error) {
				if exitErr != nil && !senderRunner.wasStopRequested() {
					statusLabel.SetText("Sender exited with error")
					updateState("Error", color.NRGBA{R: 183, G: 28, B: 28, A: 255})
					appendLog(logBox, "[sender] exited: "+exitErr.Error())
					return
				}
				statusLabel.SetText("Sender stopped")
				updateState("Stopped", color.NRGBA{R: 99, G: 102, B: 106, A: 255})
				appendLog(logBox, "[sender] exited normally")
			},
		)
		if err != nil {
			statusLabel.SetText("Failed to start sender")
			updateState("Start failed", color.NRGBA{R: 183, G: 28, B: 28, A: 255})
			appendLog(logBox, "[sender] start failed: "+err.Error())
			return
		}
		updateState("Running", color.NRGBA{R: 27, G: 94, B: 32, A: 255})
	})
	startSender.Importance = widget.HighImportance

	stopSender := widget.NewButtonWithIcon("Stop Sender", theme.MediaStopIcon(), func() {
		if !senderRunner.isRunning() {
			statusLabel.SetText("Sender is not running")
			updateState("Not running", color.NRGBA{R: 99, G: 102, B: 106, A: 255})
			return
		}
		statusLabel.SetText("Stopping sender...")
		updateState("Stopping", color.NRGBA{R: 183, G: 109, B: 0, A: 255})
		appendLog(logBox, "Stopping sender...")
		senderRunner.stop()
	})
	stopSender.Importance = widget.DangerImportance

	senderForm := widget.NewForm(
		widget.NewFormItem("Protocol (-tu)", senderProtocol),
		widget.NewFormItem("Destination IP (-da)", senderIP),
		widget.NewFormItem("Destination Port (-dp)", senderPort),
		widget.NewFormItem("Message Number (-mn)", senderMsgNum),
		widget.NewFormItem("Interval microseconds (-rn)", senderInterval),
		widget.NewFormItem("Thread Number (-tn)", senderThreads),
	)

	controls := container.NewVBox(
		widget.NewLabel("Sender Parameters"),
		stateCard,
		senderChecks,
		senderForm,
		container.NewHBox(startSender, stopSender, layout.NewSpacer()),
	)
	logs := container.NewBorder(
		widget.NewLabel("Sender Logs"),
		container.NewHBox(layout.NewSpacer(), widget.NewButton("Clear Sender Logs", func() { logBox.SetText("") })),
		nil,
		nil,
		logBox,
	)

	w.SetContent(container.NewBorder(
		container.NewVBox(statusLabel),
		nil,
		nil,
		nil,
		container.NewBorder(controls, nil, nil, nil, logs),
	))
	w.SetCloseIntercept(func() {
		senderRunner.stop()
		w.Close()
	})
	w.ShowAndRun()
}